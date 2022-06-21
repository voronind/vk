Contribution
============

This section will be useful for first-time contributors


Setup environment
-----------------

For setup/build/test we use `tox <https://tox.wiki/en/latest/>`__, so you need to install it first

.. code-block:: bash

    git clone https://github.com/voronind/vk
    cd vk

    pip install virtualenv
    virtualenv venv
    source venv/bin/activate

    pip install tox


To prevent unformatted code from commit, we recommend adding a pre-commit hook or execute ``tox -e fix`` yourself before each commit

.. code-block:: bash

    pip install pre-commit
    pre-commit install


Tox targets
-----------

.. code-block:: bash

    tox             # To run tests
    tox -e docs     # To build documentation
    tox -e fix      # To format files


Testing
-------


Since some test suites use real calls to the VK API, you should create the necessary data for this and save it as environment variables. Also don't forget to add them to your repository secrets

.. list-table::
    :widths: 20, 45, 35
    :header-rows: 1

    * - Varibale
      - Description
      - How to get

    * - VK_ACCESS_TOKEN
      - Access token for VK API. We reccomend to use community token, because it doesn't have an expiration date
      - Create your community, go to its settings (API section), create API key with messages scopes

    * - VK_USER_LOGIN
      - Login from the VK account. For rare tests, you can use your account, otherwise we recommend to register a test one
      - \-

    * - VK_USER_PASSWORD
      - Password from the VK account. For rare tests, you can use your account, otherwise we recommend to register a test one
      - \-

    * - VK_GROUP_IDS
      - IDs of communities in which you have admin rights
      - Create *N* your communities, copy their IDs and pass it to env var as comma-separated list


Logging
-------

It's very useful for the module's debug to include logs to better understand what is happening

.. code-block:: python

    import vk
    import logging

    logging.basicConfig()
    logging.getLogger('vk').setLevel(logging.DEBUG)
