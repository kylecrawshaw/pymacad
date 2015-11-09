import subprocess
import os
from pymacad import ad

def _keychain(action_type, item_type, args, return_code=False):
    if item_type not in ['generic', 'internet']:
        raise Exception()
    if action_type not in ['add', 'find', 'delete']:
        raise Exception()
    action = '{0}-{1}-password'.format(action_type, item_type)
    user_keychain = os.path.expanduser('~/Library/Keychains/login.keychain')
    cmd = ['/usr/bin/security', action] + args + [user_keychain]
    if return_code:
        return subprocess.call(cmd)
    else:
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
            return out
        except subprocess.CalledProcessError as e:
            return None


def _format_principal(principal):
    p_split = principal.split('@')
    principal =  '{0}@{1}'.format(p_split[0], p_split[1].upper())
    return principal


def check_keychain(principal=None):
    if principal:
        username, realm = ad._split_principal(principal)
    else:
        if not ad.bound():
            raise ad.NotBound
        realm = ad.realms()[0]
        username=ad._get_consoleuser()
    security_args = [
        '-a', username,
        '-l', realm.upper() + ' (' + username + ')',
        '-s', realm.upper(),
        '-c', 'aapl'
    ]
    return True if _keychain('find', 'generic', security_args) else False


def pass_to_keychain(principal, password):
    """Saves password to keychain for use by kinit."""
    username, realm = ad._split_principal(principal)
    security_args = [
        '-a', username,
        '-l', realm,
        '-s', realm,
        '-c', 'aapl',
        '-T', '/usr/bin/kinit',
        '-w', str(password)
    ]
    return _keychain('add', 'generic', security_args)

def test_kerberos_password(principal, password):
    """Runs the kinit command with supplied password."""
    renew1 = subprocess.Popen(['echo', password], stdout=subprocess.PIPE)
    renew2 = subprocess.Popen(['kinit','-l','10h','--renewable',
                               '--password-file=STDIN','--keychain',
                               _format_principal(principal)],
                               stderr=subprocess.PIPE,
                               stdin=renew1.stdout,
                               stdout=subprocess.PIPE)
    renew1.stdout.close()

    out = renew2.communicate()[1]
    if 'incorrect' in out:
        return False
    elif '':
        return True
    else:
        return out

def kinit_keychain_command(principal):
    """Runs the kinit command with keychain password."""
    if not check_keychain(principal):
        return False
    try:
        subprocess.check_output(['/usr/bin/kinit', '-l', '10h', '--renewable',
                                 _format_principal(principal)])
        return True
    except:
        """exception most likely means a password mismatch,
        so we should run renewTicket again."""
        return False


def refresh_ticket():
    try:
        return_code = subprocess.check_output(['/usr/bin/kinit', '--renew'],
                                              stderr=subprocess.STDOUT)
        return True
    except subprocess.CalledProcessError:
        return False
