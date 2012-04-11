import logging
logger = logging.getLogger('cas_provider.views')
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

from . import signals

__all__ = ['login', 'validate', 'logout']


def _build_service_url(service, ticket):
    if service.find('?') == -1:
        return service + '?ticket=' + ticket
    else:
        return service + '&ticket=' + ticket


def login(request, template_name='cas/login.html', success_redirect='/account/', merge=False):
    logging.debug('CAS Provider Login view. Method is %s, merge is %s, template is %s.',
                  request.method, merge, template_name)

    service = request.GET.get('service', None)
    if service is not None:
        # Save the service on the session, for later use if we end up
        # in one of the more complicated workflows.
        request.session['service'] = service

    user = request.user

    errors = []

    if request.method == 'POST':
        if merge:
            form = MergeLoginForm(request.POST, request=request)
        else:
            form = LoginForm(request.POST, request=request)

        if form.is_valid():
            service = form.cleaned_data.get('service', None)
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
            
            if user is None:
                errors.append('Incorrect username and/or password.')
            else:
                if user.is_active:
                    auth_login(request, user)

    else:  # Not a POST...
        if merge:
            form = MergeLoginForm(initial={'service': service, 'email': request.GET.get('email')})
        else:
            form = LoginForm(initial={'service': service})

    if user is not None and user.is_authenticated():
        # We have an authenticated user.
        if not user.is_active:
            errors.append('This account is disabled.')
        else:
            if service is None:
                # Try and pull the service off the session
                service = request.session.pop('service', service)
            
            if service is None:
                # Normal internal success redirection.
                logging.debug('Redirecting to %s', success_redirect)
                return HttpResponseRedirect(success_redirect)
            else:
                # Create a service ticket and redirect to the service.
                ticket = create_service_ticket(request.user, service)
                if 'service' in request.session:
                    # Don't need this any more.
                    del request.session['service']

                url = _build_service_url(service, ticket.ticket)
                logging.debug('Redirecting to %s', url)
                return HttpResponseRedirect(url)

    logging.debug('Rendering response on %s, merge is %s', template_name, merge)
    return render_to_response(template_name, {'form': form, 'errors': errors}, context_instance=RequestContext(request))


def socialauth_login(request, template_name='cas/login.html', success_redirect='/account/'):
    """ Similiar to login but user has been authenticated already through social auth.
        This step authenticates the login and generates a service ticket.
    """
    user = request.user
    user.backend = 'django.contrib.auth.backends.ModelBackend'
    service = request.session.pop('service', '/')
    errors = []
    if user is not None:
        if user.is_active:
            auth_login(request, user)
            if service is not None:
                ticket = create_service_ticket(user, service)
                return HttpResponseRedirect(_build_service_url(service, ticket.ticket))
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
    logger.info('Validating ticket %s for %s', ticket_string, service)
    if service is not None and ticket_string is not None:
        try:
            ticket = ServiceTicket.objects.get(ticket=ticket_string)
        except ServiceTicket.DoesNotExist:
            logger.exception("Tried to validate with an invalid ticket %s for %s", ticket_string, service)
        except Exception as e:
            logger.exception('Got an exception: %s', e)
        else:
            username = ticket.user.username
            ticket.delete()

            results = signals.on_cas_collect_histories.send(sender=validate, for_email=ticket.user.email)
            histories = '\n'.join('\n'.join(rs) for rc, rs in results)
            logger.info('Validated %s %s', username, "(also %s)" % histories if histories else '')
            return HttpResponse("yes\n%s\n%s" % (username, histories))

    logger.info('Validation failed.')
    return HttpResponse("no\n\n")
    

def logout(request, template_name='cas/logout.html'):
    url = request.GET.get('url', None)
    auth_logout(request)
    return render_to_response(template_name, {'url': url}, context_instance=RequestContext(request))
