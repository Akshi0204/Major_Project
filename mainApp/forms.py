from django import forms
from .models import *

class UserForm(forms.ModelForm):
    class Meta:
        model = User
        fields = '__all__'
        exclude = ('id',)
        widgets = {
            'name' : forms.TextInput(attrs={'class':'form-control'}),
            'email' : forms.EmailInput(attrs={'class':'form-control'}),
            'password' : forms.PasswordInput(attrs={'class':'form-control'}),
            'phone' : forms.TextInput(attrs={'class':'form-control'}),
            'department' : forms.TextInput(attrs={'class':'form-control'}),
        }
        
   
class ChangePasswordForm(forms.Form):
    oldPassword = forms.CharField(widget=forms.PasswordInput(attrs={'class':'form-control'}))
    newPassword = forms.CharField(widget=forms.PasswordInput(attrs={'class':'form-control'}))
    confirmPassword = forms.CharField(widget=forms.PasswordInput(attrs={'class':'form-control'}))



from django import forms

from django import forms

class PlotForm(forms.Form):
    y_axis = forms.ChoiceField(
        choices=[
            ('Windspeed', 'Windspeed'),
            ('Height', 'Height'),
            ('WindDirection', 'WindDirection'),
            ('Temperature', 'Temperature'),
            ('Pressure', 'Pressure'),
            ('Humidity', 'Humidity')
        ],
        label="Select Y-Axis Parameter",
        required=True
    )

    x_axis = forms.ChoiceField(
        choices=[
            ('Date', 'Date'),
            ('Windspeed', 'Windspeed'),
            ('Height', 'Height'),
            ('WindDirection', 'WindDirection'),
            ('Temperature', 'Temperature'),
            ('Pressure', 'Pressure'),
            ('Humidity', 'Humidity')
        ],
        label="Select X-Axis Parameter",
        required=True
    )

    graph_type = forms.ChoiceField(
        choices=[
            ('histogram', 'Histogram'),
            ('bar', 'Bar Graph'),
            ('line', 'Line Graph'),
            ('scatter', 'Scatter Plot')
        ],
        label="Select Graph Type",
        required=True
    )