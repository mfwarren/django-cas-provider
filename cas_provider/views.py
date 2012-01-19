import logging
import urllib

from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.contrib.auth import authenticate
from django.contrib.auth import login as auth_login, logout as auth_logout
from django.core.urlresolvers import reverse

from forms import LoginForm, MergeLoginForm
from models import ServiceTicket
from utils import create_service_ticket
from exceptions import SameEmailMismatchedPasswords

__all__ = ['login', 'validate', 'logout']


def login(request, template_name='cas/login.html', success_redirect='/account/', merge=False):
    logging.debug('CAS Provider Login view. Method is %s, merge is %s, template is %s.',
                  request.method, merge, template_name)
    service = request.GET.get('service', None)
    if service is not None:
        request.session['service'] = service
    if request.user.is_authenticated():
        if service is not None:
            ticket = create_service_ticket(request.user, service)
            if service.find('?') == -1:
                url = service + '?ticket=' + ticket.ticket
                logging.debug('Redirecting to %s', url)
                return HttpResponseRedirect(url)
            else:
                url = service + '&ticket=' + ticket.ticket
                logging.debug('Redirecting to %s', url)
                return HttpResponseRedirect()
        else:
            logging.debug('Redirecting to %s', success_redirect)
            return HttpResponseRedirect(success_redirect)
    errors = []
    if request.method == 'POST':
        if merge:
            logging.debug('Using mergeloginform, email is %' % request.GET.get('email'))
            form = MergeLoginForm(request.POST, request=request)
        else:
            form = LoginForm(request.POST, request=request)

        if form.is_valid():
            try:
                auth_args = dict(username=form.cleaned_data['email'],
                                 password=form.cleaned_data['password'])
                if merge:
                    # We only want to send the merge argument if it's
                    # True. If it it's False, we want it to propagate
                    # through the auth backends properly.
                    auth_args['merge'] = merge
                user = authenticate(**auth_args)
            except SameEmailMismatchedPasswords:
                # Need to merge the accounts?
                if merge:
                    # We shouldn't get here...
                    raise
                else:
                    base_url = reverse('cas_provider_merge')
                    args = dict(
                        success_redirect=success_redirect,
                        email=form.cleaned_data['email'],
                        )
                    if service is not None:
                        args['service'] = service
                    args = urllib.urlencode(args)

                    url = '%s?%s' % (base_url, args)
                    logging.debug('Redirecting to %s', url)
                    return HttpResponseRedirect(url)
            
            if user is not None:
                if user.is_active:
                    auth_login(request, user)
                    if service is not None:
                        ticket = create_service_ticket(user, service)
                        url = service + '?ticket=' + ticket.ticket
                        logging.debug('Redirecting to %s', url)
                        return HttpResponseRedirect(url)
                    else:
                        logging.debug('Redirecting to %s', success_redirect)
                        return HttpResponseRedirect(success_redirect)
                else:
                    errors.append('This account is disabled.')
            else:
                    errors.append('Incorrect username and/or password.')
    else:
        if merge:
            logging.debug('Using mergeloginform, email is %' % request.GET.get('email'))
            form = MergeLoginForm(initial={'service': service, 'email': request.GET.get('email')})
        else:
            logging.debug('Using normal login form.')
            form = LoginForm(initial={'service': service})
    logging.debug('Rendering response on %s, merge is %s', template_name, merge)
    return render_to_response(template_name, {'form': form, 'errors': errors}, context_instance=RequestContext(request))


def socialauth_login(request, template_name='cas/login.html', success_redirect='/account/'):
    """ Similiar to login but user has been authenticated already through social auth.
        This step authenticates the login and generates a service ticket.
    """
    user = request.user
    user.backend = 'django.contrib.auth.backends.ModelBackend'
    if request.session.has_key('service'):
        service = request.session['service']
        del request.session['service']
    else:
        service = '/'
    errors = []
    if user is not None:
        if user.is_active:
            auth_login(request, user)
            if service is not None:
                ticket = create_service_ticket(user, service)
                return HttpResponseRedirect(service + '?ticket=' + ticket.ticket)
            else:
                return HttpResponseRedirect(success_redirect)
        else:
            errors.append('This account is disabled.')
    else:
            errors.append('Incorrect username and/or password.')
    return render_to_response(template_name, {'errors': errors}, context_instance=RequestContext(request))


def validate(request):
    service = request.GET.get('service', None)
    ticket_string = request.GET.get('ticket', None)
    if service is not None and ticket_string is not None:
        try:
            ticket = ServiceTicket.objects.get(ticket=ticket_string)
            username = ticket.user.username
            ticket.delete()
            return HttpResponse("yes\n%s\n" % username)
        except:
            pass
    return HttpResponse("no\n\n")
    

def logout(request, template_name='cas/logout.html'):
    url = request.GET.get('url', None)
    auth_logout(request)
    return render_to_response(template_name, {'url': url}, context_instance=RequestContext(request))
