import datetime
import bcrypt
from django.shortcuts import render, redirect,HttpResponse
from .models import *
from .forms import *
global ttUrl
ttUrl = 'media/1.jpg'

# Create your views here.

def login(request):
    if request.session.has_key('adminEmail'):
        return redirect('adminHome')
    elif request.session.has_key('userEmail'):
        return redirect('userHome')
    else:
        return render(request, 'login.html')

from .models import UserActivity  # Ensure you import the UserActivity model

from django.shortcuts import render, redirect
import bcrypt
from .models import UserCredentials, User

def userLogin(request):
    if request.session.has_key('userEmail'):
        return redirect('userHome')  # Redirect if the user is already logged in

    if request.method == 'POST':
        email = request.POST.get('typeEmailX')  # Get the email from the form
        password = request.POST.get('typePasswordX')  # Get the password from the form

        try:
            user_credentials = UserCredentials.objects.get(email=email)  # Fetch user credentials
            # Verify the password
            if bcrypt.checkpw(password.encode('utf-8'), user_credentials.password.encode('utf-8')):
                # Set session variables if password is correct
                request.session['userEmail'] = email
                return redirect('userHome')  # Redirect to user home page
            else:
                return render(request, 'userLogin.html', {'message': 'Invalid password'})  # Password mismatch
        except UserCredentials.DoesNotExist:
            return render(request, 'userLogin.html', {'message': 'User not found'})  # User does not exist

    return render(request, 'userLogin.html')  # Render login page if GET request

def logout(request):
    if request.session.has_key('userEmail'):
        user_instance = User.objects.get(email=request.session['userEmail'])
        UserActivity.objects.create(user=user_instance, activity_type='logout', ip_address=request.META.get('REMOTE_ADDR'))

        del request.session['userEmail']
        del request.session['userPassword']
    if request.session.has_key('adminEmail'):
        del request.session['adminEmail']
        del request.session['adminPassword']
    return redirect('login')

from django.shortcuts import render
from .models import UserActivity

from django.shortcuts import render
from .models import UserActivity

def userActivities(request):
    if request.session.has_key('userEmail'):  # Check if user is logged in
        user_email = request.session['userEmail']
        activities = UserActivity.objects.filter(user__email=user_email).order_by('-timestamp')
        return render(request, 'user_activities.html', {'activities': activities})
    else:
        return HttpResponse("<h1>Please login to see your activity history</h1>")
def adminLogin(request):
    if request.session.has_key('adminEmail'):
        return redirect('adminHome')
    elif request.session.has_key('userEmail'):
        return redirect('userHome')
    else:
        return render(request, 'adminLogin.html')
from django.shortcuts import render, redirect
import bcrypt
from .models import User, Report, UserCredentials

def userHome(request):
    if request.session.has_key('userEmail'):
        user = User.objects.get(email=request.session['userEmail'])
        report = Report.objects.get(user=user)
        return render(request, 'userHome.html', {'user': user, 'report': report})  # <-- Added return statement

    elif request.session.has_key('adminEmail'):
        return redirect('adminHome')

    elif request.method == 'POST':
        email = request.POST.get('typeEmailX')  # Use .get() for safety
        password = request.POST.get('typePasswordX')

        try:
            user = UserCredentials.objects.get(email=email)
        except UserCredentials.DoesNotExist:
            return redirect('userLogin')

        salt = user.salt
        hashedPassword = bcrypt.hashpw(password.encode('utf-8'), salt.encode('utf-8')).decode('utf-8')

        if hashedPassword != user.password:
            return redirect('userLogin')

        # Store user session data
        request.session['userEmail'] = email
        request.session['userPassword'] = hashedPassword
        request.session.modified = True

        user = User.objects.get(email=email)
        report = Report.objects.get(user=user)
        return render(request, 'userHome.html', {'user': user, 'report': report})  # <-- Added return statement

    else:
        return redirect('login')

    
def adminHome(request):
    if request.session.has_key('adminEmail'):
        return render(request, 'adminHome.html')
    elif request.session.has_key('userEmail'):
        return redirect('userHome')
    elif request.method=='POST':
        email = request.POST['typeEmailX']
        password = request.POST['typePasswordX']
        try:
            admin = AdminCredentials.objects.get(email=email)
        except:
            return redirect('adminLogin')
        salt = admin.salt
        hashedPassword = bcrypt.hashpw(password.encode('utf-8'),salt.encode('utf-8')).decode('utf-8')
        if hashedPassword!=admin.password:
            return redirect('adminLogin')
        request.session['adminEmail'] = email
        request.session['adminPassword'] = hashedPassword
        request.session.modified = True
        request.session.save()
        return render(request, 'adminHome.html')
    else:
        return redirect('login')


from django.shortcuts import render, redirect
import bcrypt
from .models import UserCredentials, AdminCredentials, User

def changePassword(request):
    user_email = request.session.get('userEmail')  # Use .get() to avoid KeyError
    admin_email = request.session.get('adminEmail')

    if user_email:
        if request.method == "POST":
            old_password = request.POST.get('oldPassword')
            new_password = request.POST.get('newPassword')
            confirm_password = request.POST.get('confirmPassword')

            if new_password != confirm_password:
                return render(request, 'changepassword.html', {'changepasswordform': ChangePasswordForm(), 'message': 'Passwords do not match'})

            user_cred = UserCredentials.objects.get(email=user_email)
            salt = user_cred.salt
            hashed_old_password = bcrypt.hashpw(old_password.encode('utf-8'), salt.encode('utf-8')).decode('utf-8')

            if hashed_old_password == user_cred.password:
                salt = bcrypt.gensalt().decode('utf-8')
                hashed_new_password = bcrypt.hashpw(new_password.encode('utf-8'), salt.encode('utf-8')).decode('utf-8')

                # Update password
                user_cred.password = hashed_new_password
                user_cred.salt = salt
                user_cred.save()

                # Also update User model password
                user = User.objects.get(email=user_email)
                user.password = new_password
                user.save()

                return redirect('logout')
            else:
                return render(request, 'changepassword.html', {'changepasswordform': ChangePasswordForm(), 'message': 'Old Password is incorrect'})

        return render(request, 'changepassword.html', {'changepasswordform': ChangePasswordForm(), 'message': ''})

    elif admin_email:
        if request.method == "POST":
            old_password = request.POST.get('oldPassword')
            new_password = request.POST.get('newPassword')
            confirm_password = request.POST.get('confirmPassword')

            if new_password != confirm_password:
                return render(request, 'changepassword.html', {'changepasswordform': ChangePasswordForm(), 'message': 'Passwords do not match'})

            admin_cred = AdminCredentials.objects.get(email=admin_email)
            salt = admin_cred.salt
            hashed_old_password = bcrypt.hashpw(old_password.encode('utf-8'), salt.encode('utf-8')).decode('utf-8')

            if hashed_old_password == admin_cred.password:
                salt = bcrypt.gensalt().decode('utf-8')
                hashed_new_password = bcrypt.hashpw(new_password.encode('utf-8'), salt.encode('utf-8')).decode('utf-8')

                # Update password
                admin_cred.password = hashed_new_password
                admin_cred.salt = salt
                admin_cred.save()

                return redirect('logout')
            else:
                return render(request, 'changepassword.html', {'changepasswordform': ChangePasswordForm(), 'message': 'Old Password is incorrect'})

        return render(request, 'changepassword.html', {'changepasswordform': ChangePasswordForm(), 'message': ''})

    else:
        return redirect('login')


import bcrypt
from django.shortcuts import render, redirect
from .models import User, UserCredentials, Report  # Ensure proper imports
from .forms import UserForm  # Import your user form

def addUser(request):
    if request.session.has_key('adminEmail'):
        if request.method == "POST":
            form = UserForm(request.POST)
            if form.is_valid():
                # Hash the password
                salt = bcrypt.gensalt()
                hashedPassword = bcrypt.hashpw(form.cleaned_data['password'].encode('utf-8'), salt)

                # Create and save the UserCredentials instance
                user_credentials = UserCredentials(
                    email=form.cleaned_data['email'],
                    password=hashedPassword.decode('utf-8'),
                    salt=salt.decode('utf-8')
                )
                user_credentials.save()

                # Create a User instance
                user = User(
                    email=form.cleaned_data['email'],  # Assuming you have an email field
                    name=form.cleaned_data['name'],
                    phone=form.cleaned_data['phone'],
                    department=form.cleaned_data['department'],    # Assuming you have a name field
                )
                user.save()  # Save the User instance

                # Create the Report instance using the User instance
                report = Report(user=user, report=ttUrl)  # Ensure ttUrl is defined
                report.save()

            return render(request, 'addUser.html', {'userform': UserForm()})
        else:
            return render(request, 'addUser.html', {'userform': UserForm()})
    else:
        return redirect('login')



def manageUsers(request):
    if request.session.has_key('adminEmail'):
        users = User.objects.all()
        return render(request, 'manageUsers.html',{'users':users})
    else:
        return redirect('login')

def updateUser(request, id):
    if request.session.has_key('adminEmail'):
        if request.method == "POST":
            user = User.objects.get(id=id)
            user.name = request.POST['name']
            user.email = request.POST['email']
            user.password = request.POST['password']
            cred = UserCredentials.objects.get(email=request.POST['email'])
            salt = cred.salt
            hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), salt.encode('utf-8'))
            cred.password = hashed_password.decode('utf-8')
            user.phone = request.POST['phone']
            user.department = request.POST['department']
            user.save()
            return redirect('manageUsers')
        else:
            user = User.objects.get(id=id)
            return render(request, 'updateUser.html', {'user': user})
    else:
        return redirect('login')





def deleteUser(request,id):
    if request.session.has_key('adminEmail'):
        user = User.objects.get(id=id)
        try:
            UserCredentials.objects.get(email=user.email).delete()
        except:
            pass

        user.delete()
        return redirect('manageUsers')
    else:
        return redirect('login')







def updateReport(request):
    global ttUrl
    if request.session.has_key('adminEmail'):
        if request.method=="POST":
            users = Report.objects.all()
            for user in users:
                user.report = request.FILES['report']
                user.save()
            ttUrl = "media/reports/" + str(request.FILES['report'])
            return redirect('adminHome')
        else:
            return render(request, 'updateReport.html',{'ttUrl':ttUrl})
    else:
        return redirect('login')
    
    
from django.shortcuts import render
from .models import Report





from django.shortcuts import render
from .models import Sheets
from .resources import SheetsResource
from django.contrib import messages
from tablib import Dataset
import csv,io

from django.shortcuts import render
from .models import Sheets
from .resources import SheetsResource
from django.contrib import messages
from tablib import Dataset
import csv,io

def upload(request):
    if request.method == 'POST':
        sheets_resource = SheetsResource()
        dataset = Dataset()
        new_sheets = request.FILES['myfile']

        if not new_sheets.name.endswith('csv'):
            messages.info(request,'Please Upload the CSV File only')
            return render(request,'upload.html')

        data_set = new_sheets.read().decode('UTF-8')
        io_string = io.StringIO(data_set)
        next(io_string)
        for column in csv.reader(io_string, delimiter=',', quotechar="|"):
            created = Sheets.objects.update_or_create(
                Height=column[0],
                Windspeed=column[1],
                WindDirection=column[2],
                Temperature=column[3],
                Pressure=column[4],
                Humidity=column[5],
                Date=column[6])
    return render(request, 'upload.html')
# Create your views here.

def datasearch(request):
    if request.method=="POST":
        searchdate=request.POST.get('Date')
        search=Sheets.objects.filter(Date=searchdate)

        return render(request,'datasearch.html',{"data":search})
    else:
        display=Sheets.objects.all()

        return render(request,'datasearch.html',{"data":display})
from django.shortcuts import render
from mainApp.models import Sheets
import pandas as pd
from plotly.offline import plot
import plotly.express as px
from .forms import PlotForm

def plot_view(request):
    qs = Sheets.objects.all()
    data = [
        {
            'Windspeed': x.Windspeed,  
            'Height': x.Height,
            'WindDirection': x.WindDirection,
            'Temperature': x.Temperature,
            'Pressure': x.Pressure,
            'Humidity': x.Humidity,
            'Date': x.Date,
        } for x in qs
    ]

    df = pd.DataFrame(data)

    form = PlotForm(request.POST or None)
    plot_div = None

    if request.method == 'POST':
        print(request.POST)  # Debugging line to see the posted data
        if form.is_valid():
            selected_y_param = form.cleaned_data['y_axis']  # Use 'y_axis' instead of 'parameters'
            selected_x_param = form.cleaned_data['x_axis']
            selected_graph_type = form.cleaned_data['graph_type']
            
            # Generate the appropriate plot based on the selected graph type
            if selected_graph_type == 'histogram':
                fig = px.histogram(
                    df,
                    x=selected_y_param,
                    title=f"Histogram of {selected_y_param} Distribution",
                    labels={selected_y_param: selected_y_param}
                )
            
            elif selected_graph_type == 'bar':
                fig = px.bar(
                    df,
                    x=selected_x_param,
                    y=selected_y_param,
                    title=f"Bar Graph of {selected_y_param} Over {selected_x_param}",
                    labels={selected_y_param: selected_y_param, selected_x_param: selected_x_param}
                )
            
            elif selected_graph_type == 'line':
                fig = px.line(
                    df,
                    x=selected_x_param,
                    y=selected_y_param,
                    title=f"Line Graph of {selected_y_param} Over {selected_x_param}",
                    labels={selected_y_param: selected_y_param, selected_x_param: selected_x_param}
                )
            
            elif selected_graph_type == 'scatter':
                fig = px.scatter(
                    df,
                    x=selected_x_param,
                    y=selected_y_param,
                    title=f"Scatter Plot of {selected_y_param} Over {selected_x_param}",
                    labels={selected_y_param: selected_y_param, selected_x_param: selected_x_param}
                )
            
            plot_div = plot(fig, output_type="div")

    context = {
        'form': form,
        'plot_div': plot_div,
    }
    return render(request, 'plot.html', context)

import openai
import os
from dotenv import load_dotenv
from django.shortcuts import render

# Load environment variables
load_dotenv()

# Get OpenAI API key from environment variables
api_key = os.getenv("OPENAI_KEY", None)

def chatbot(request):
    chatbot_response = None
    if api_key is not None and request.method == 'POST':
        openai.api_key = api_key
        user_input = request.POST.get('user_input')

        try:
            # Use the new ChatCompletion API
            response = openai.ChatCompletion.create(
                model='gpt-3.5-turbo',  # You can use another model if you prefer
                messages=[
                    {"role": "user", "content": user_input}
                ],
                max_tokens=256,
                temperature=0.5
            )
            # Extract the response text
            chatbot_response = response['choices'][0]['message']['content'].strip()
        except Exception as e:
            chatbot_response = f"Error: {str(e)}"  # Capture any errors during the API call

    return render(request, 'main.html', {'chatbot_response': chatbot_response}) 

from django.http import HttpResponse
from .models import Sheets
import csv

def download(request):
    # Create the HttpResponse object with the appropriate CSV header
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="sheets_data.csv"'

    writer = csv.writer(response)
    writer.writerow(['Height', 'Windspeed', 'WindDirection', 'Temperature', 'Pressure', 'Humidity', 'Date'])  # Add header row

    # Fetch all records from the Sheets model
    sheets = Sheets.objects.all().values_list('Height', 'Windspeed', 'WindDirection', 'Temperature', 'Pressure', 'Humidity', 'Date')

    # Write data rows
    for sheet in sheets:
        writer.writerow(sheet)

    return response

def download_page(request):
    return render(request, 'download.html')



def download(request):
    # Create the HttpResponse object with the appropriate CSV header
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="sheets_data.csv"'

    writer = csv.writer(response)
    writer.writerow(['Height', 'Windspeed', 'WindDirection', 'Temperature', 'Pressure', 'Humidity', 'Date'])  # Add header row

    # Fetch all records from the Sheets model
    sheets = Sheets.objects.all().values_list('Height', 'Windspeed', 'WindDirection', 'Temperature', 'Pressure', 'Humidity', 'Date')

    # Write data rows
    for sheet in sheets:
        writer.writerow(sheet)

    return response

import csv
from django.http import HttpResponse
from .models import User  # Ensure you import the User model

def download_users(request):
    # Create the HttpResponse object with the appropriate CSV header
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="users_list.csv"'

    writer = csv.writer(response)
    writer.writerow(['ID', 'Name', 'Email', 'Phone', 'Department'])  # Add header row

    # Fetch all records from the User model
    users = User.objects.all().values_list('id', 'name', 'email', 'phone', 'department')

    # Write data rows
    for user in users:
        writer.writerow(user)

    return response
def download_users_page(request):
    return render(request, 'downloadUsers.html')