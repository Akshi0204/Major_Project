---Instructions---

1.Prerequisuites :
  **Install Latest Git** -->  https://git-scm.com/download
  **Install Latest Python** -->  https://www.python.org/downloads/

2.Steps to Follow :
**Open a Terminal**
  cmd in Windows
  shell in Linux/MacOS
  
**Enter the Following**
**Open terminal in the Extracted folder**
  pip install virtualenv
  virtualenv django-env
  
**For Windows** :
cd django-env/Scripts
activate
cd ../..

**For Linux/MacOS** :
cd django-env/bin
source activate
cd ../..

**For All** :
pip install -r requirements.txt
python manage.py makemigrations
python manage.py migrate
python manage.py clearsessions
python manage.py runserver

**Open a Web Browser and Enter the following** :
http://localhost:8000
