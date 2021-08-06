from django import forms
from django.contrib.auth.models import User, auth
from django.forms import fields,ModelForm
from .models import Account, InputData
from django.contrib.auth.forms import UserCreationForm
class RegistrationForm(UserCreationForm):
    email = forms.EmailField(max_length=60, help_text='Required. Add a valide email address')

    class Meta:
        model = Account
        fields = ("email","username","password1","password2")
        


class MyForm(forms.ModelForm):

     class Meta:
        model = Account
        fields = ['is_prouser',]

# class MyForm(forms.ModelForm):
#     class Meta:
#         model = Account
#         fields = ('is_prouser',)
#     def clean_prouser(self):
#         prouser = self.cleaned_data['is_prouser']
#         try:
#             account = Account.objects.exclude(pk=self.instance.pk).get(prouser = prouser)
#         except Account.DoseNotExist:
#             return prouser
#         raise forms.ValidationError('prouser is already True')
#     def save(self, commit=True):
#         account = super(MyForm, self).save(commit=False)
#         account.is_prouser = self.cleaned_data['is_prouser']
#         if commit:
#             account.save()
#         return account

class UploadData(forms.ModelForm):

     class Meta:
        model = InputData
        fields =["username","Total_sequenced","Sequenced_last_week","Uploaded_IGIB_SFTP","Uploaded_NIBMG_DataHub","Uploaded_GISAID","Any_collaboration",]
        # fields = '__all__'