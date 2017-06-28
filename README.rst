=====
Makwa
=====


.. image:: https://travis-ci.org/AntonKueltz/makwa.svg?branch=master
    :target: https://travis-ci.org/AntonKueltz/makwa
.. image:: https://badge.fury.io/py/makwa.svg
    :target: https://badge.fury.io/py/makwa

Makwa is a password hashing function designed by Thomas Pornin. This implementation is in pure python with no 3rd party dependencies. From the `Passwords14 Slides`_:

.. code::

    Makwa is a candidate to the Password Hashing Competition.
    
    Main characteristics:
    * based on modular arithmetics
    * CPU-only cost (not memory-hard)
    * algebraic structure enables advanced features: offline work
    * factor increase, fast path, escrow
    * can be delegated
    * named after the Ojibwe name for the American black bear
    
Reference Material
==================

- `Homepage`_
- `Spec Paper`_ 
- `Passwords14 Slides`_

.. _Homepage: http://www.bolet.org/makwa/
.. _Spec Paper: http://www.bolet.org/makwa/makwa-spec-20150422.pdf
.. _Passwords14 Slides: http://www.bolet.org/makwa/Makwa-Passwords14LV.pdf

Installation
============

.. code:: bash

    pip install makwa

Usage
=====

.. code:: python

    from makwa import Makwa
    
    m = Makwa()  # option h and work_factor parameter e.g. Makwa(work_factor=8192, h=sha1)
    hashed = m.hash('password')  # optional salt parameter e.g. m.hash('password', salt='salt')
    
    
