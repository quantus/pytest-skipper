# -*- coding: utf-8 -*-
from coverage import Coverage
from git import Repo
import difflib
import re

current_git_head_sha = Repo('.').commit().hexsha
# If project folder is "/foo/bar", assume code is stored in "/foo/bar/bar"
source_folder = Repo('.').working_tree_dir.split('/')[-1]
test_folder = 'tests'

current_cov = None
current_fixture = None
fixture_scopes = {}
tracing = False


def create_coverage():
    coverage = Coverage(
        config_file=False,
        source=[source_folder],
        include=[source_folder + '/*'],
    )
    coverage._warn_no_data = False
    return coverage


def pytest_runtest_call(item):
    global current_cov, current_fixture, tracing
    if not tracing:
        return

    if current_fixture:
        stop_fixture_capture(current_fixture)

    current_fixture = None
    current_cov.start()


def pytest_runtest_teardown(item, nextitem):
    global current_cov, current_fixture, fixture_scopes, tracing
    if not tracing:
        return

    current_cov.stop()
    scopes = extract_scopes_from_coverage(current_cov)
    current_cov.erase()

    failed = False

    for fixture_name in item.fixturenames:
        if fixture_name != 'request':  # pytest internal fixture
            if fixture_name in fixture_scopes:
                scopes.extend(fixture_scopes[fixture_name])
            else:
                print('Fixture execution trace missing, tracing ignored')
                failed = True

    # Remove duplicates
    scopes = list(set(scopes))

    if not failed:
        save_scopes_to_db(current_git_head_sha, item.nodeid, scopes)


def pytest_fixture_setup(fixturedef, request):
    global current_cov, current_fixture, fixture_scopes, tracing
    if not tracing:
        return

    if not current_cov:
        current_cov = create_coverage()
    elif current_fixture:
        stop_fixture_capture(current_fixture)

    current_fixture = fixturedef.argname
    current_cov.start()


def stop_fixture_capture(name):
    global current_cov, current_fixture, fixture_scopes
    current_cov.stop()

    scopes = extract_scopes_from_coverage(current_cov)
    fixture_scopes[current_fixture] = scopes

    current_cov.erase()
    return scopes


def pytest_report_header(config):
    global tracing

    tracing = config.getvalue("tracing")

    if tracing:
        r = Repo('.')
        if r.commit(r.head).diff(None):
            raise Exception(
                'Uncommitted changes in repository, tracing impossible'
            )

    return "Tracer %s, skipper %s" % (
        ("enabled" if config.getvalue("tracing") else "disabled"),
        ("listing" if config.getvalue("dry-run-skipper") else (
            "enabled" if config.getvalue("skipper") else "disabled"
        ))
    )


def pytest_collection_modifyitems(session, config, items):
    if config.getvalue("skipper") or config.getvalue("dry-run-skipper"):
        import sqlite3
        conn = sqlite3.connect('skipper.db')
        c = conn.cursor()
        commit_shas = [
            row for row,
            in c.execute('SELECT DISTINCT(git_sha) FROM scopes').fetchall()
        ]
        potential_scopes = [
            (commit_sha, get_changed_scopes_in_source(commit_sha))
            for commit_sha in commit_shas
        ]
        if not potential_scopes:
            print('No previous traces found, re-running all tests')
            return

        potential_scopes = sorted(
            potential_scopes,
            key=lambda x: (
                x[0] != current_git_head_sha,  # Use current git commit
                'global' in x[1][0],  # Avoid global changes
                len(x[1][0]),  # Avoid lots of changes
                x[0]  # Make deterministic
            )
        )
        base_commit_sha, (scopes, dirty_test_files) = potential_scopes[0]
        print('Potential traces %r' % (
            [(x[0], len(x[1][0])) for x in potential_scopes]
        ))
        print('Using trace %s' % base_commit_sha)
        print('Found modifications to following scopes: %r' % sorted(
            list(scopes)
        ))

        if 'global' in scopes:
            print('Changes to global scope, re-running all tests')
            if config.getvalue("dry-run-skipper"):
                tests = items[:]
                items[:] = []
                config.hook.pytest_deselected(items=tests)
            return

        skippable_test_names = set([
            l for l, in c.execute(
                "SELECT DISTINCT(test)"
                "FROM scopes "
                "WHERE git_sha = :git_sha AND "
                "NOT test IN ("
                "  SELECT test FROM scopes "
                "  WHERE git_sha = :git_sha AND "
                "  scope IN (%s))" % (
                    ','.join("'%s'" % escape(s) for s in scopes)
                ),
                {'git_sha': base_commit_sha},
            ).fetchall()
        ])

        tests_to_run = []
        tests_to_skip = []

        for item in items:
            if (
                item.nodeid in skippable_test_names and
                not any(item.nodeid.startswith(t) for t in dirty_test_files)
            ):
                tests_to_skip.append(item)
            else:
                tests_to_run.append(item)

        if config.getvalue("dry-run-skipper"):
            print('Following tests can not be skipped: ')
            for test in tests_to_run:
                print(test.nodeid)

            print('Result: Can skip %d test(s), need to run %d test(s)' % (
                len(tests_to_skip),
                len(tests_to_run)
            ))

            tests = items[:]
            items[:] = []
            config.hook.pytest_deselected(items=tests)
            return

        if (
            config.getvalue('tracing') and
            tests_to_skip and
            current_git_head_sha != base_commit_sha
        ):
            print('Moving skipped tests to the latest commit')
            c.execute(
                "UPDATE scopes SET git_sha=:new_git_sha "
                "WHERE git_sha=:old_git_sha AND test IN (%s)" % (
                    ', '.join(
                        "'%s'" % escape(item.nodeid) for item in tests_to_skip
                    )
                ),
                {
                    'new_git_sha': current_git_head_sha,
                    'old_git_sha': base_commit_sha
                }
            )

        print('Result: managed to skip %d test(s), running %d test(s)' % (
            len(tests_to_skip),
            len(tests_to_run)
        ))
        items[:] = tests_to_run
        config.hook.pytest_deselected(items=tests_to_skip)


def pytest_addoption(parser):
    group = parser.getgroup("general")
    group.addoption(
        '--skipper', action='store_true', dest="skipper",
        help="rerun only the tests that have changes in execution path.")
    group.addoption(
        '--tracer', action='store_true', dest="tracing",
        help="Trace and store each test's execution path.")
    group.addoption(
        '--dry-run-skipper', action='store_true', dest="dry-run-skipper",
        help="Only list the tests that have changes in execution path.")


def create_scopes(lines):
    from StringIO import StringIO
    data = StringIO(''.join(lines))

    scopes = []
    current_class = None
    current_function = None
    line = data.readline()
    while line:
        if line.endswith('\n'):
            line = line[:-1]
        if line:
            if not line.startswith(' ' * 4):
                current_class = None
                current_function = None
            elif not line.startswith(' ' * 8):
                if current_class:
                    current_function = None

        scopes.append(
            (current_class + '.' + current_function)
            if current_class and current_function
            else current_function or 'global'
        )
        if line:
            if line.startswith('class '):
                current_class = line[6:line.find('(')]
                while line.find(':') == -1:
                    line = data.readline()
                    scopes.append('global')
            elif line.startswith('def '):
                current_function = line[4:line.find('(')]
                while line.find(':') == -1:
                    line = data.readline()
                    scopes.append('global')
            elif line.startswith('    def ') and current_class:
                current_function = line[8:line.find('(')]
                while line.find(':') == -1:
                    line = data.readline()
                    scopes.append('global')

        line = data.readline()
    return scopes


def get_changed_scopes_in_source(commit_sha):
    dirty_test_files = {}
    r = Repo('.')
    diffs = r.commit(commit_sha).diff(None)
    scopes = set()
    for d in diffs:
        if (d.a_path or d.b_path).startswith(test_folder + '/'):
            print('Commit %s: change to %s, assume test changes' % (
                commit_sha, (d.a_path or d.b_path)
            ))
            dirty_test_files.add(d.a_path or d.b_path)
            continue
        elif not (d.a_path or d.b_path).startswith(source_folder + '/'):
            print('Commit %s: change to %s, assume global changes' % (
                commit_sha, (d.a_path or d.b_path)
            ))
            return ['global'], []
        a_content_lines = (
            d.a_blob.data_stream.read().split('\n') if d.a_blob else []
        )
        b_content_lines = (
            d.b_blob.data_stream.read().split('\n') if d.b_blob else []
        )
        if not b_content_lines:
            b_content_lines = [
                l[:-1]
                for l in open(d.a_blob.path, 'r').readlines()
            ] + ['']
        changes = list(
            difflib.unified_diff(a_content_lines, b_content_lines, n=0)
        )
        lines = []
        for line in [l for l in changes if l.startswith('@')]:
            lines.append(re.match(
                '@@ -(\d+),?(\d+)? \+(\d+),?(\d+)? @@\n',
                line
            ).groups())
        a_lines = []
        b_lines = []
        for line in lines:
            a_lines.append(int(line[0]))
            if line[1]:
                for i in range(int(line[1])):
                    a_lines.append(int(line[0]) + i)
            b_lines.append(int(line[2]))
            if line[3]:
                for i in range(int(line[3])):
                    b_lines.append(int(line[2]) + i)

        a_file_scopes = create_scopes([l + '\n' for l in a_content_lines])
        b_file_scopes = create_scopes([l + '\n' for l in b_content_lines])

        for a in a_lines:
            if a != 0:
                scopes.add(a_file_scopes[a-1])
        for b in b_lines:
            if b != 0:
                scopes.add(b_file_scopes[b-1])
    return scopes, dirty_test_files


def extract_scopes_from_coverage(cov):
    d = cov.get_data()
    executed_lines = {}
    for filename in d.measured_files():
        line_numbers = d.lines(filename)
        if line_numbers and filename.endswith('.py'):
            executed_lines[filename] = line_numbers

    executed_scopes = {}
    for filename, line_numbers in executed_lines.items():
        source = open(filename, 'r').readlines()
        if not source:
            continue  # Empty __init__.py files
        scopes = create_scopes(source)
        scopes2 = set([scopes[i - 1] for i in line_numbers]) - set(['global'])
        if scopes2:
            executed_scopes[filename] = scopes2

    formated_scopes = sorted([
        scope
        for (filename, scopes3) in executed_scopes.items()
        for scope in scopes3
    ])
    return formated_scopes


def save_scopes_to_db(git_sha, test_id, scopes):
    import sqlite3
    conn = sqlite3.connect('skipper.db')
    c = conn.cursor()
    try:
        c.execute('CREATE TABLE scopes(git_sha text, scope text, test text)')
    except sqlite3.OperationalError:
        conn.rollback()
        c = conn.cursor()

    c.execute(
        "DELETE FROM scopes WHERE git_sha=? AND test=?",
        (git_sha, test_id)
    )
    c.executemany(
        "INSERT INTO scopes VALUES (?, ?, ?)",
        [(git_sha, scope, test_id) for scope in scopes]
    )
    conn.commit()
    conn.close()


def escape(value):
    return value.replace('\'', '\'\'')
