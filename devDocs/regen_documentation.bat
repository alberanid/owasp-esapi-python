SET EPYDOC_PATH=C:\Python26\Scripts\epydoc.py
SET OUTPUT_DIR=C:\ESAPIPython\doc\

hg rm %OUTPUT_DIR%*

%EPYDOC_PATH% -o %OUTPUT_DIR% esapi

hg add %OUTPUT_DIR%*