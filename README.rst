pytest-skipper
===================================

.. image:: https://travis-ci.org/quantus/pytest-skipper.svg?branch=master
    :target: https://travis-ci.org/quantus/pytest-skipper
    :alt: See Build Status on Travis CI

.. image:: https://ci.appveyor.com/api/projects/status/github/quantus/pytest-skipper?branch=master
    :target: https://ci.appveyor.com/project/quantus/pytest-skipper/branch/master
    :alt: See Build Status on AppVeyor

A plugin that executes only the tests with changes in execution path

----

This `Pytest`_ plugin was generated with `Cookiecutter`_ along with `@hackebrot`_'s `Cookiecutter-pytest-plugin`_ template.


Features
--------

* TODO


Requirements
------------

* TODO


Installation
------------

You can install "pytest-skipper" via `pip`_ from `PyPI`_::

    $ pip install pytest-skipper


Usage
-----

Capture execution trace
-----------------------

    $ py.test --trace

This will run the full test suite and record coverage scopes (= name of executed functions)
for each test. The scopes are stored in sqlite database ``skipper.db``. The git repo may not
have any uncommitted changes when execution trace is recorded.

Execute only tests with changes in execution path
-------------------------------------------------

    $ py.test --skipper

This command compares your projects git repo state against traces in scope database and selects
the execution trace with least code changes. After this the program calculates all scopes with
changes and uses those to select only the tests that have changes in their execution path.

Update execution trace while running few tests
----------------------------------------------

    $ py.test --skipper --trace

You can use ``--trace`` and ``--skipper`` arguments at the same time to update the previous
execution trace to the latest version without re-running all the tests. Execution traces are
stored after each test case, so it is possible to terminate this command and continue it later.

List tests with changes
-----------------------

    $ py.test --dry-run-skipper

Same as ``--skipper``, but instead of running the tests, only outputs them. Useful to see what
tests need to be updated after code change.

Similar projects
----------------
 - `pytest-testmon`_
 - `smother`_

Contributing
------------
Contributions are very welcome. Tests can be run with `tox`_, please ensure
the coverage at least stays the same before you submit a pull request.

License
-------

Distributed under the terms of the `MIT`_ license, "pytest-skipper" is free and open source software


Issues
------

If you encounter any problems, please `file an issue`_ along with a detailed description.

.. _`Cookiecutter`: https://github.com/audreyr/cookiecutter
.. _`@hackebrot`: https://github.com/hackebrot
.. _`MIT`: http://opensource.org/licenses/MIT
.. _`BSD-3`: http://opensource.org/licenses/BSD-3-Clause
.. _`GNU GPL v3.0`: http://www.gnu.org/licenses/gpl-3.0.txt
.. _`Apache Software License 2.0`: http://www.apache.org/licenses/LICENSE-2.0
.. _`cookiecutter-pytest-plugin`: https://github.com/pytest-dev/cookiecutter-pytest-plugin
.. _`file an issue`: https://github.com/quantus/pytest-skipper/issues
.. _`pytest`: https://github.com/pytest-dev/pytest
.. _`tox`: https://tox.readthedocs.io/en/latest/
.. _`pip`: https://pypi.python.org/pypi/pip/
.. _`PyPI`: https://pypi.python.org/pypi
.. _`pytest-testmon`: https://github.com/tarpas/pytest-testmon
.. _`smother`: https://github.com/ChrisBeaumont/smother
