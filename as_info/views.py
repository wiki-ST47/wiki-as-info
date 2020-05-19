from django.conf import settings
from django.contrib import messages
from django.contrib.auth import logout
from django.shortcuts import render
from as_info.forms import SearchForm
from flare.tools.whoisip import WhoisLookup
import ipaddress
import MySQLdb
import pywikibot
import requests.utils
import re
import subprocess
import urllib.parse


def run_whois(prefix, whois):
    cmd = f"whois {prefix['prefix']}"
    result = subprocess.run(cmd.split(' '), stdout=subprocess.PIPE)
    stdout = result.stdout.decode("latin-1")
    route = re.findall("route6?:\s+(\S+)", stdout)
    if route:
        prefix['route'] = route[0]
    asn = re.findall("origin:\s+AS(\d+)", stdout)
    if asn:
        prefix['asn'] = asn[0]
    net = re.findall("netname:\s+(\S+)", stdout)
    if net:
        prefix['net'] = net[0]
    org = re.findall("org-name:\s+(.+)", stdout)
    if org:
        prefix['org'] = org[0]
    if not org and not net:
        # Try again without prefix size
        firstip = prefix['prefix'][0]
        cmd = f"whois {prefix['prefix'][0]}"
        result = subprocess.run(cmd.split(' '), stdout=subprocess.PIPE)
        stdout = result.stdout.decode("latin-1")
        key = f"{prefix['prefix'][0]} - {prefix['prefix'][-1]}"
        if key in stdout or str(prefix['prefix']) in stdout:
            route = re.findall("route6?:\s+(\S+)", stdout)
            if route:
                prefix['route'] = route[0]
            asn = re.findall("origin:\s+AS(\d+)", stdout)
            if asn:
                prefix['asn'] = asn[0]
            net = re.findall("netname:\s+(\S+)", stdout)
            if net:
                prefix['net'] = net[0]
            org = re.findall("org-name:\s+(.+)", stdout)
            if org:
                prefix['org'] = org[0]

    if not asn:
        # Backup, get ASN from Flare
        ip, masklen = str(prefix['prefix']).split('/')
        rn = whois.asndb.radix.search_exact(ip, int(masklen))
        if rn:
            prefix['asn'] = rn.asn

def index(request):
    context = {}
    context['form'] = SearchForm()
    return render(request, 'index.html', context)


def docs(request):
    context = {}
    return render(request, 'docs.html', context)


def search(request):
    context = {}
    form = SearchForm(request.GET)
    context['form'] = form
    if form.is_valid():
        # Clear out any old data just in case
        pywikibot.config.authenticate = {}

        # Load up the site
        site_kwargs = {'code': 'en', 'fam': 'wikipedia'}
        wiki_url = form.cleaned_data.get('wiki_url')
        base_url = "https://"+wiki_url+"/wiki/"
        if wiki_url:
            site_kwargs = {'url': base_url}
        try:
            site = pywikibot.Site(**site_kwargs)
        except pywikibot.exceptions.SiteDefinitionError:
            form.add_error('wiki_url',
                "Unable to find this wiki. Please check the domain and "
                "try again. You provided "+wiki_url+", so we expected "
                +base_url+" to be recognized by pywikibot - but it "
                "wasn't."
            )
            return render(request, 'index.html', context)

        # Set up authentication
        if request.user.is_authenticated:
            # TODO If it is possible to have more than one auth, we should try
            # all of them, or clear them out somehow.
            auths = request.user.social_auth.all()
            auth = auths[0]
            sitebasename = requests.utils.urlparse(site.base_url('')).netloc
            pywikibot.config.authenticate[sitebasename] = (
                settings.SOCIAL_AUTH_MEDIAWIKI_KEY,
                settings.SOCIAL_AUTH_MEDIAWIKI_SECRET,
                auth.extra_data['access_token']['oauth_token'],
                auth.extra_data['access_token']['oauth_token_secret'],
            )
            userinfo = site.getuserinfo(force=True)
            if userinfo['name'] != request.user.username:
                auth.delete()
                pywikibot.config.authenticate = {}
                messages.error(request, "We weren't able to log in to the "
                               "wiki. For faster performance, please log "
                               "in again.")
                logout(request)

        whois = WhoisLookup('flaredata/ipasn.dat', 'flaredata/asnames.txt')

        # If we have an IP, get the ASN
        ip_address = form.cleaned_data.get('ip')
        if ip_address:
            if '/' in ip_address:
                # Input validation
                ip_network = ipaddress.ip_network(ip_address).compressed
                cmd = "whois "+ip_address
                result = subprocess.run(cmd.split(' '), stdout=subprocess.PIPE)
                res = re.findall("origin:\s+AS(\d+)", result.stdout.decode("latin-1"))
                if res:
                    asns = res
                else:
                    asns = [whois.get_asn(ip_address.split('/')[0])]
            else:
                # Input validation
                ip_address = ipaddress.ip_address(ip_address).compressed
                cmd = "whois "+ip_address
                result = subprocess.run(cmd.split(' '), stdout=subprocess.PIPE)
                res = re.findall("origin:\s+AS(\d+)", result.stdout.decode("latin-1"))
                if res:
                    asns = res
                else:
                    asns = [whois.get_asn(ip_address)]
            if not asns:
                form.add_error('ip',
                    "Unable to find an ASN matching this IP address or "
                    "range in the ASN database."
                )
                return render(request, 'index.html', context)
        else:
            asn = form.cleaned_data.get('asn')
            if not asn:
                form.add_error('asn',
                    "You must provide either an IP or an ASN."
                )
                return render(request, 'index.html', context)
            asns = [asn]

        # Get list of prefixes
        prefixes = []
        for asn in asns:
            try:
                prefixes.extend(whois.asndb.get_as_prefixes(asn))
            except TypeError:
                pass # No prefixes for this ASN
        prefixes = [ipaddress.ip_network(x) for x in list(set(prefixes))]
        pre_aggregation_prefixes = prefixes

        # Perform prefix aggregation
        uniq_prefixes = []
        for prefix in prefixes:
            shadowed_by = [x for x in prefixes
                           if x.version == prefix.version
                           and x != prefix
                           and x.supernet_of(prefix)]
            if not shadowed_by:
                uniq_prefixes.append(prefix)

        uniq_v4_prefixes = list(ipaddress.collapse_addresses([x for x in uniq_prefixes if x.version == 4]))
        uniq_v6_prefixes = list(ipaddress.collapse_addresses([x for x in uniq_prefixes if x.version == 6]))
        uniq_prefixes = []
        for v4_prefix in uniq_v4_prefixes:
            if v4_prefix.prefixlen < 16:
                uniq_prefixes.extend(v4_prefix.subnets(new_prefix=16))
            else:
                uniq_prefixes.append(v4_prefix)
        for v6_prefix in uniq_v6_prefixes:
            if v6_prefix.prefixlen < 19:
                uniq_prefixes.extend(v6_prefix.subnets(new_prefix=19))
            else:
                uniq_prefixes.append(v6_prefix)

        prefixes = [{'prefix': x} for x in uniq_prefixes]

        # Get block data for prefixes
        for prefix in prefixes:
            prefix['block'] = list(site.blocks(iprange=prefix['prefix'].compressed))
            if prefix['block']:
                prefix['blockAO'] = 'anononly' in prefix['block'][0]
                prefix['blockACB'] = 'nocreate' in prefix['block'][0]
            prefix['blocklog'] = list(site.logevents(page="User:"+prefix['prefix'].compressed, logtype="block"))
            if prefix['blocklog']:
                prefix['blocks'] = len([x for x in prefix['blocklog'] if x.action() == 'block'])
                prefix['unblocks'] = len([x for x in prefix['blocklog'] if x.action() == 'unblock'])

        # Get contribs data for prefixes
        for prefix in prefixes:
            if prefix['prefix'].version == 4:
                groups = int(prefix['prefix'].prefixlen / 8)
                mw_prefix = '.'.join(prefix['prefix'][0].exploded.split('.')[0:groups]) + '.'
            else:
                groups = int(prefix['prefix'].prefixlen / 16)
                mw_prefix = ':'.join(prefix['prefix'][0].compressed.split(':')[0:groups]) + ':'
            prefix['mw_prefix'] = mw_prefix
            contribs = list(site.usercontribs(userprefix=mw_prefix))
            contribs = [x for x in contribs
                        if re.search('^([\d.]+|[a-fA-F\d:]+)$', x['user'])
                        and ipaddress.ip_address(x['user']) in prefix['prefix']]
            prefix['contribs'] = len(contribs)
            if contribs:
                prefix['latest_contrib'] = contribs[0]['timestamp']

        # Get whois data for prefixes
        for prefix in prefixes:
            run_whois(prefix, whois)

            if 'route' not in prefix or not prefix['route']:
                # This may be a prefix which we aggregated. If it isn't already blocked, we should
                # see if the pre-aggregation prefixes are.
                sub_prefixes = [x for x in pre_aggregation_prefixes
                                if x.version == prefix['prefix'].version
                                and x != prefix['prefix']
                                and x.subnet_of(prefix['prefix'])]
                sub_prefixes = sorted(sub_prefixes)
                sub_prefixes = [{'prefix': x} for x in sub_prefixes]
                for sub_prefix in sub_prefixes:
                    # Block data
                    sub_prefix['block'] = list(site.blocks(iprange=sub_prefix['prefix'].compressed))
                    if sub_prefix['block']:
                        sub_prefix['blockAO'] = 'anononly' in sub_prefix['block'][0]
                        sub_prefix['blockACB'] = 'nocreate' in sub_prefix['block'][0]
                    sub_prefix['blocklog'] = list(site.logevents(page="User:"+sub_prefix['prefix'].compressed, logtype="block"))
                    if sub_prefix['blocklog']:
                        sub_prefix['blocks'] = len([x for x in sub_prefix['blocklog'] if x.action() == 'block'])
                        sub_prefix['unblocks'] = len([x for x in sub_prefix['blocklog'] if x.action() == 'unblock'])

                    # Whois data
                    run_whois(sub_prefix, whois)

                if sub_prefixes:
                    prefix['sub_prefixes'] = sub_prefixes
                    if not prefix['block']:
                        blocked_subs = [x for x in sub_prefixes if x['block']]
                        aggregated_blocked_subs = list(ipaddress.collapse_addresses(
                            [x['prefix'] for x in blocked_subs]
                        ))
                        if aggregated_blocked_subs and prefix['prefix'] == aggregated_blocked_subs[0]:
                            prefix['block_aggregate'] = True

                    # Try to roll up ASN
                    if 'asn' not in prefix or not prefix['asn']:
                        candidate_asns = list(set([x['asn'] for x in sub_prefixes if 'asn' in x and x['asn']]))
                        if len(candidate_asns) == 1:
                            prefix['asn'] = candidate_asns[0]

        # Try to enrich ASNs
        asnlist = []
        for prefix in prefixes:
            if 'asn' in prefix and prefix['asn'] and prefix['asn'] not in asnlist:
                asnlist.append(prefix['asn'])
            if 'sub_prefixes' in prefix:
                for sub_prefix in prefix['sub_prefixes']:
                    if 'asn' in sub_prefix and sub_prefix['asn'] and sub_prefix['asn'] not in asnlist:
                        asnlist.append(sub_prefix['asn'])
        for asn in asnlist:
            cmd = f"whois AS{asn}"
            result = subprocess.run(cmd.split(' '), stdout=subprocess.PIPE)
            stdout = result.stdout.decode("latin-1")
            orgname = re.findall("org-name:\s+(.+)", stdout)
            if orgname:
                for prefix in prefixes:
                    if 'asn' in prefix and asn == prefix['asn']:
                        prefix['asnorgname'] = orgname[0]
                    if 'sub_prefixes' in prefix:
                        for prefix in prefix['sub_prefixes']:
                            if 'asn' in prefix and asn == prefix['asn']:
                                prefix['asnorgname'] = orgname[0]

        context['prefixes'] = prefixes

        indexphp = 'https:' + site.siteinfo['server'] + site.siteinfo['script']
        context['indexphp'] = indexphp

        # Clean up
        pywikibot.config.authenticate = {}

        return render(request, 'as_info/search.html', context)

    return render(request, 'index.html', context)
