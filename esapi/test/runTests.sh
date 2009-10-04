#!/bin/bash

nosetests --with-coverage --cover-package=esapi.reference --cover-package=esapi.codecs *.py
