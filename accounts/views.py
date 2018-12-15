from django.urls import reverse_lazy
from django.views import generic
from django.contrib.auth import login, authenticate, logout

from .forms import CustomUserCreationForm

from django.http import HttpResponseRedirect, HttpResponse
from django.shortcuts import render, redirect

from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from .tokens import account_activation_token
from django.contrib.auth.models import User
from django.core.mail import EmailMessage
from django.contrib.auth import get_user_model


def register(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        print(form.errors)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = False
            user.save()
            current_site = get_current_site(request)
            mail_subject = 'Account Activation'
            message = render_to_string('acc_active_email.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)).decode(),
                'token': account_activation_token.make_token(user),
            })
            to_email = form.cleaned_data.get('emailp')
            email = EmailMessage(
                mail_subject, message, to=[to_email]
            )
            email.send()
            return render(request, 'registration/signup.html', {'form': form, 'error': "Check your Email"})
            # username = form.cleaned_data.get('username')
            # password = form.cleaned_data.get('password1')
            # user = authenticate(username=username, password=password)
            # login(request, user)
            # return HttpResponseRedirect('/')

        else:
            print(form.errors)
            return render(request, 'registration/signup.html', {'form': form, 'error': form.errors})

    else:
        form = CustomUserCreationForm(request.POST)
        return render(request, 'registration/signup.html', {'form': form})


def activate(request, uidb64, token):
    User = get_user_model()
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        print(uid)
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        login(request, user)
        return HttpResponseRedirect('/')
    else:
        return HttpResponse('Activation link is invalid!')


def userlogin(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(username=username, password=password)
        if user is not None:
            if user.is_active:
                login(request, user)
                return HttpResponseRedirect('/')

            else:
                return render(request, 'registration/login.html', {'error': 'Your account has been disabled'})

        else:
            return render(request, 'registration/login.html', {'error': 'Invalid Username/Password'})

    return render(request, 'registration/login.html')
