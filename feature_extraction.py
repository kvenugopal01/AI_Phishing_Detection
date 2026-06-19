import re
import socket
import urllib.parse
import requests
from bs4 import BeautifulSoup

# Helper function to add details to our features dictionary.
# A beginner style function that keeps everything simple.
def add_feature_detail(features_dict, details_dict, feat_name, display_name, val, description):
    features_dict[feat_name] = val
    
    # set the status and badge strings based on values
    if val == 1:
        status_str = "safe"
        badge_str = "Legitimate"
    elif val == 0:
        status_str = "suspicious"
        badge_str = "Suspicious"
    else:
        status_str = "danger"
        badge_str = "Phishing"
        
    details_dict[feat_name] = {
        "display": display_name,
        "val": val,
        "status": status_str,
        "badge": badge_str,
        "description": description
    }

def extract_all_features(url_string):
    # Clean the input URL
    original_url = url_string.strip()
    
    # Check if url has http/https protocol, if not add it
    if not re.match(r'^https?://', original_url, re.IGNORECASE):
        url = 'http://' + original_url
    else:
        url = original_url

    # Parse the URL components
    parsed_url = urllib.parse.urlparse(url)
    domain_name = parsed_url.netloc
    
    # Strip port number if any
    if ":" in domain_name:
        domain = domain_name.split(":")[0]
    else:
        domain = domain_name
        
    scheme = parsed_url.scheme.lower()
    path = parsed_url.path

    # We store features and detailed statuses in dictionaries
    features = {}
    details = {}

    # Feature 1: IP address check
    # Check if domain has an IP address layout instead of hostname string
    ip_match = re.compile(
        r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|'
        r'^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$', re.IGNORECASE
    )
    if ip_match.match(domain):
        add_feature_detail(features, details, 'having_IPhaving_IP_Address', 'IP Address in Domain', -1, 'IP address used instead of domain name.')
    else:
        add_feature_detail(features, details, 'having_IPhaving_IP_Address', 'IP Address in Domain', 1, 'Domain name is standard string.')

    # Feature 2: URL Length
    url_len = len(url)
    if url_len < 54:
        add_feature_detail(features, details, 'URLURL_Length', 'URL Length', 1, f'URL length ({url_len} chars) is within safe limit.')
    elif url_len >= 54 and url_len <= 75:
        add_feature_detail(features, details, 'URLURL_Length', 'URL Length', 0, f'URL length ({url_len} chars) is suspicious.')
    else:
        add_feature_detail(features, details, 'URLURL_Length', 'URL Length', -1, f'URL length ({url_len} chars) is high, common in phishing.')

    # Feature 3: URL Shortening Services
    # Check if domain uses a redirection shortener domain
    shorteners = (
        r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|'
        r'cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|'
        r'snipurl\.com|short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|'
        r'fic\.kr|loopt\.us|doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|'
        r'bit\.do|lnkd\.in|db\.tt|qr\.ae|adf\.ly|bitly\.com|cur\.lv|ity\.im|q\.gs|po\.st|'
        r'bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
        r'prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|twe\.ly|'
        r'doublet\.com.br|shortto\.com|tny\.im'
    )
    if re.search(shorteners, domain, re.IGNORECASE):
        add_feature_detail(features, details, 'Shortining_Service', 'URL Shortening Service', -1, 'Uses a common URL shortening service.')
    else:
        add_feature_detail(features, details, 'Shortining_Service', 'URL Shortening Service', 1, 'No URL shortening service detected.')

    # Feature 4: Check for @ symbol
    if '@' in url:
        add_feature_detail(features, details, 'having_At_Symbol', '@ Symbol in URL', -1, 'Contains "@" symbol, which can mask domain.')
    else:
        add_feature_detail(features, details, 'having_At_Symbol', '@ Symbol in URL', 1, 'No "@" symbol found.')

    # Feature 5: Double slash redirect check
    last_double_slash = url.rfind('//')
    if last_double_slash > 7:
        add_feature_detail(features, details, 'double_slash_redirecting', 'Double Slash Redirect', -1, 'Contains "//" after the protocol for redirecting.')
    else:
        add_feature_detail(features, details, 'double_slash_redirecting', 'Double Slash Redirect', 1, 'No double slash redirect pattern.')

    # Feature 6: Prefixes or Suffixes
    if '-' in domain:
        add_feature_detail(features, details, 'Prefix_Suffix', 'Prefix/Suffix (Hyphen)', -1, 'Domain contains hyphen (-), common in spoofing.')
    else:
        add_feature_detail(features, details, 'Prefix_Suffix', 'Prefix/Suffix (Hyphen)', 1, 'No hyphens in domain.')

    # Feature 7: Sub domains count
    sub_domain_str = domain
    if sub_domain_str.startswith('www.'):
        sub_domain_str = sub_domain_str[4:]
    dot_count = sub_domain_str.count('.')
    if dot_count <= 1:
        add_feature_detail(features, details, 'having_Sub_Domain', 'Subdomain Count', 1, 'Legitimate subdomain count (0 or 1).')
    elif dot_count == 2:
        add_feature_detail(features, details, 'having_Sub_Domain', 'Subdomain Count', 0, 'Suspicious subdomain count (2).')
    else:
        add_feature_detail(features, details, 'having_Sub_Domain', 'Subdomain Count', -1, 'High subdomain count, characteristic of phishing.')

    # Feature 8: SSL Final State
    if scheme == 'https':
        add_feature_detail(features, details, 'SSLfinal_State', 'SSL Final State', 1, 'HTTPS protocol is active.')
    else:
        add_feature_detail(features, details, 'SSLfinal_State', 'SSL Final State', -1, 'Unsecured HTTP protocol.')

    # Feature 9: Domain registration length (mock value based on SSL state)
    if scheme == 'https':
        add_feature_detail(features, details, 'Domain_registeration_length', 'Domain Registration Length', 1, 'Inferred domain registration validity period.')
    else:
        add_feature_detail(features, details, 'Domain_registeration_length', 'Domain Registration Length', -1, 'Inferred domain registration validity period.')

    # Feature 11: Non-standard Port
    try:
        url_port = parsed_url.port
    except Exception:
        url_port = None

    if url_port and url_port not in (80, 443):
        add_feature_detail(features, details, 'port', 'Non-Standard Port', -1, f'Running on a non-standard port ({url_port}).')
    else:
        add_feature_detail(features, details, 'port', 'Non-Standard Port', 1, 'Uses standard web port (80 or 443).')

    # Feature 12: HTTPS keyword token in hostname
    if 'https' in domain.lower():
        add_feature_detail(features, details, 'HTTPS_token', 'HTTPS Token in Hostname', -1, 'Hostname contains "https" token (phishing trick).')
    else:
        add_feature_detail(features, details, 'HTTPS_token', 'HTTPS Token in Hostname', 1, 'Domain does not spoof HTTPS keyword.')

    # Perform DNS lookup to get IP address and check DNS record status
    html = ""
    redirect_count = 0
    resolved_ip = ""
    resolved_dns = 1

    try:
        resolved_ip = socket.gethostbyname(domain)
        resolved_dns = 1
    except Exception:
        resolved_dns = -1

    add_feature_detail(features, details, 'DNSRecord', 'DNS Record', resolved_dns, 'Domain resolves in DNS.' if resolved_dns == 1 else 'Domain does not resolve in DNS.')

    # Try fetching HTML page contents
    if resolved_dns == 1:
        try:
            browser_headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36'
            }
            # Verify=False to allow checking questionable sites
            response = requests.get(url, timeout=2.5, headers=browser_headers, verify=False, allow_redirects=True)
            html = response.text
            redirect_count = len(response.history)
        except Exception:
            html = ""

    # Check BeautifulSoup status
    if html:
        try:
            soup = BeautifulSoup(html, 'html.parser')
        except Exception:
            soup = None
    else:
        soup = None

    # Feature 10: Favicon Source validation
    if soup:
        favicon_val = 1
        for link_tag in soup.find_all('link'):
            tag_rel = link_tag.get('rel', [])
            if isinstance(tag_rel, str):
                tag_rel = [tag_rel]
            
            # check if tag is a favicon
            is_icon = False
            for rel_val in tag_rel:
                if rel_val.lower() in ['icon', 'shortcut icon']:
                    is_icon = True
                    break
            
            if is_icon:
                icon_href = link_tag.get('href', '')
                fav_parsed = urllib.parse.urlparse(icon_href)
                if fav_parsed.netloc and fav_parsed.netloc != domain:
                    favicon_val = -1
                    break
        add_feature_detail(features, details, 'Favicon', 'Favicon Source', favicon_val, 'Favicon loaded from external domain.' if favicon_val == -1 else 'Favicon loaded from internal domain.')
    else:
        if resolved_dns == -1:
            fav_fallback = -1
            fav_desc = 'Domain does not resolve; favicon cannot be verified.'
        else:
            fav_fallback = 0
            fav_desc = 'No page DOM; favicon assumed suspicious.'
        add_feature_detail(features, details, 'Favicon', 'Favicon Source', fav_fallback, fav_desc)

    # Feature 13: Request URL (External assets ratio)
    if soup:
        external_assets = 0
        total_assets = 0
        for element in soup.find_all(['img', 'audio', 'embed', 'iframe', 'src']):
            element_src = element.get('src', '')
            if element_src:
                total_assets = total_assets + 1
                src_parsed = urllib.parse.urlparse(element_src)
                if src_parsed.netloc and src_parsed.netloc != domain:
                    external_assets = external_assets + 1
                    
        if total_assets == 0:
            pct = 0.0
        else:
            pct = (external_assets / total_assets) * 100.0

        if pct < 22.0:
            add_feature_detail(features, details, 'Request_URL', 'Request URL Assets', 1, f'Only {pct:.1f}% of assets loaded externally (<22%).')
        elif pct >= 22.0 and pct <= 61.0:
            add_feature_detail(features, details, 'Request_URL', 'Request URL Assets', 0, f'{pct:.1f}% of assets loaded externally (22-61%).')
        else:
            add_feature_detail(features, details, 'Request_URL', 'Request URL Assets', -1, f'{pct:.1f}% of assets loaded externally (>61%).')
    else:
        if resolved_dns == -1:
            req_fallback = -1
            req_desc = 'Domain does not resolve; assets assumed malicious.'
        else:
            req_fallback = 0
            req_desc = 'No page DOM; assets assumed suspicious.'
        add_feature_detail(features, details, 'Request_URL', 'Request URL Assets', req_fallback, req_desc)

    # Feature 14: URL of Anchor (external links ratio)
    if soup:
        external_anchors = 0
        total_anchors = 0
        for anchor in soup.find_all('a'):
            anchor_href = anchor.get('href', '').strip()
            total_anchors = total_anchors + 1
            if anchor_href in ('', '#', '#content', 'javascript:void(0);'):
                external_anchors = external_anchors + 1
            else:
                a_parsed = urllib.parse.urlparse(anchor_href)
                if a_parsed.netloc and a_parsed.netloc != domain:
                    external_anchors = external_anchors + 1
        
        if total_anchors == 0:
            pct = 0.0
        else:
            pct = (external_anchors / total_anchors) * 100.0

        if pct < 31.0:
            add_feature_detail(features, details, 'URL_of_Anchor', 'Anchor Link Targets', 1, f'Only {pct:.1f}% of anchor links point externally or empty (<31%).')
        elif pct >= 31.0 and pct <= 67.0:
            add_feature_detail(features, details, 'URL_of_Anchor', 'Anchor Link Targets', 0, f'{pct:.1f}% of anchor links point externally or empty (31-67%).')
        else:
            add_feature_detail(features, details, 'URL_of_Anchor', 'Anchor Link Targets', -1, f'{pct:.1f}% of anchor links point externally or empty (>67%).')
    else:
        if resolved_dns == -1:
            anchor_fallback = -1
            anchor_desc = 'Domain does not resolve; links assumed malicious.'
        else:
            anchor_fallback = 0
            anchor_desc = 'No page DOM; links assumed suspicious.'
        add_feature_detail(features, details, 'URL_of_Anchor', 'Anchor Link Targets', anchor_fallback, anchor_desc)

    # Feature 15: Links in script, link and meta tags
    if soup:
        external_tags = 0
        total_tags = 0
        for tag in soup.find_all(['link', 'script', 'meta']):
            tag_link = tag.get('href', '') or tag.get('content', '') or tag.get('src', '')
            if tag_link:
                total_tags = total_tags + 1
                t_parsed = urllib.parse.urlparse(tag_link)
                if t_parsed.netloc and t_parsed.netloc != domain:
                    external_tags = external_tags + 1
                    
        if total_tags == 0:
            pct = 0.0
        else:
            pct = (external_tags / total_tags) * 100.0

        if pct < 17.0:
            add_feature_detail(features, details, 'Links_in_tags', 'External Links in Tags', 1, f'Only {pct:.1f}% of tag links point externally (<17%).')
        elif pct >= 17.0 and pct <= 81.0:
            add_feature_detail(features, details, 'Links_in_tags', 'External Links in Tags', 0, f'{pct:.1f}% of tag links point externally (17-81%).')
        else:
            add_feature_detail(features, details, 'Links_in_tags', 'External Links in Tags', -1, f'{pct:.1f}% of tag links point externally (>81%).')
    else:
        if resolved_dns == -1:
            tags_fallback = -1
            tags_desc = 'Domain does not resolve; tag links assumed malicious.'
        else:
            tags_fallback = 0
            tags_desc = 'No page DOM; tag links assumed suspicious.'
        add_feature_detail(features, details, 'Links_in_tags', 'External Links in Tags', tags_fallback, tags_desc)

    # Feature 16: SFH (Server Form Handler)
    if soup:
        sfh_val = 1
        for form in soup.find_all('form'):
            form_action = form.get('action', '').strip()
            if not form_action or form_action.lower() == 'about:blank':
                sfh_val = -1
                break
            form_parsed = urllib.parse.urlparse(form_action)
            if form_parsed.netloc and form_parsed.netloc != domain:
                sfh_val = 0
        add_feature_detail(features, details, 'SFH', 'Server Form Handler', sfh_val, 
                           'Form handler is safe.' if sfh_val == 1 else 
                           ('Form action is empty or about:blank.' if sfh_val == -1 else 'Form action points to external domain.'))
    else:
        if resolved_dns == -1:
            sfh_fallback = -1
            sfh_desc = 'Domain does not resolve; form handler assumed malicious.'
        else:
            sfh_fallback = 0
            sfh_desc = 'No page DOM; form handler assumed suspicious.'
        add_feature_detail(features, details, 'SFH', 'Server Form Handler', sfh_fallback, sfh_desc)

    # Feature 17: Submitting to email (mailto:)
    if soup:
        email_submit = 1
        for form in soup.find_all('form'):
            action_str = form.get('action', '').lower()
            if 'mailto:' in action_str:
                email_submit = -1
                break
        if email_submit == 1:
            if 'mailto:' in html.lower() or 'mail()' in html.lower():
                email_submit = -1
        add_feature_detail(features, details, 'Submitting_to_email', 'Submitting to Email', email_submit, 'Contains mailto: links, sending user input to email.' if email_submit == -1 else 'No email submission forms found.')
    else:
        if resolved_dns == -1:
            email_fallback = -1
            email_desc = 'Domain does not resolve; cannot verify email submission.'
        else:
            email_fallback = 0
            email_desc = 'No page DOM; email submission unknown.'
        add_feature_detail(features, details, 'Submitting_to_email', 'Submitting to Email', email_fallback, email_desc)

    # Feature 18: Abnormal URL structures
    if parsed_url.hostname != domain:
        add_feature_detail(features, details, 'Abnormal_URL', 'Abnormal URL Structure', -1, 'Hostname mismatch or anomalous URL encoding.')
    else:
        add_feature_detail(features, details, 'Abnormal_URL', 'Abnormal URL Structure', 1, 'URL structure is normal.')

    # Feature 19: Page Redirection Jump counts
    if redirect_count <= 1:
        add_feature_detail(features, details, 'Redirect', 'Redirections', 0, f'Minimal page redirection ({redirect_count} jumps).')
    elif redirect_count >= 2 and redirect_count < 4:
        add_feature_detail(features, details, 'Redirect', 'Redirections', 1, f'Moderate page redirection ({redirect_count} jumps).')
    else:
        add_feature_detail(features, details, 'Redirect', 'Redirections', -1, f'Excessive page redirection ({redirect_count} jumps).')

    # Feature 20: Mouseover window status bar change scripts
    if soup:
        on_mouse = 1
        for element in soup.find_all(onmouseover=True):
            if 'window.status' in element.get('onmouseover', ''):
                on_mouse = -1
                break
        if on_mouse == 1:
            if 'window.status' in html:
                on_mouse = -1
        add_feature_detail(features, details, 'on_mouseover', 'Mouseover Status Bar Edit', on_mouse, 'Disguises URLs in status bar on hover.' if on_mouse == -1 else 'No status bar spoofing scripts.')
    else:
        if resolved_dns == -1:
            mouse_fallback = -1
            mouse_desc = 'Domain does not resolve; cannot verify mouseover scripts.'
        else:
            mouse_fallback = 0
            mouse_desc = 'No page DOM; mouseover status unknown.'
        add_feature_detail(features, details, 'on_mouseover', 'Mouseover Status Bar Edit', mouse_fallback, mouse_desc)

    # Feature 21: Right click menu block checks
    if soup:
        right_click = 1
        cleaned_html = html.replace(' ', '')
        if 'event.button==2' in cleaned_html or ('preventDefault()' in html and 'contextmenu' in html):
            right_click = -1
        add_feature_detail(features, details, 'RightClick', 'Disabled Right-Click', right_click, 'Right-click menu disabled on page.' if right_click == -1 else 'Right-click menu is active.')
    else:
        if resolved_dns == -1:
            rc_fallback = -1
            rc_desc = 'Domain does not resolve; cannot verify right-click scripts.'
        else:
            rc_fallback = 0
            rc_desc = 'No page DOM; right-click status unknown.'
        add_feature_detail(features, details, 'RightClick', 'Disabled Right-Click', rc_fallback, rc_desc)

    # Feature 22: Popup windows with user input forms
    if soup:
        popup_val = 1
        if 'prompt(' in html or 'window.open(' in html:
            popup_val = 0
        add_feature_detail(features, details, 'popUpWidnow', 'Pop-up Window Forms', popup_val, 'Contains popup alert or window creation code.' if popup_val == 0 else 'No suspicious popup scripts.')
    else:
        if resolved_dns == -1:
            popup_fallback = -1
            popup_desc = 'Domain does not resolve; cannot verify popup scripts.'
        else:
            popup_fallback = 0
            popup_desc = 'No page DOM; popup status unknown.'
        add_feature_detail(features, details, 'popUpWidnow', 'Pop-up Window Forms', popup_fallback, popup_desc)

    # Feature 23: Iframe Insertion checking
    if soup:
        has_iframe = soup.find('iframe')
        if has_iframe:
            add_feature_detail(features, details, 'Iframe', 'Iframe Insertion', -1, 'Contains <iframe> tag (can hide malicious pages).')
        else:
            add_feature_detail(features, details, 'Iframe', 'Iframe Insertion', 1, 'No iframe tags detected.')
    else:
        if resolved_dns == -1:
            iframe_fallback = -1
            iframe_desc = 'Domain does not resolve; cannot verify iframe usage.'
        else:
            iframe_fallback = 0
            iframe_desc = 'No page DOM; iframe status unknown.'
        add_feature_detail(features, details, 'Iframe', 'Iframe Insertion', iframe_fallback, iframe_desc)

    # Feature 24: Age of domain (mock feature based on SSL state)
    if scheme == 'https':
        add_feature_detail(features, details, 'age_of_domain', 'Domain Age', 1, 'Inferred domain age based on security status.')
    else:
        add_feature_detail(features, details, 'age_of_domain', 'Domain Age', -1, 'Inferred domain age based on security status.')
        
    # Feature 26: Web traffic rank indicator (mock feature based on SSL state)
    if scheme == 'https':
        add_feature_detail(features, details, 'web_traffic', 'Web Traffic Rank', 0, 'Inferred traffic rank status.')
    else:
        add_feature_detail(features, details, 'web_traffic', 'Web Traffic Rank', -1, 'Inferred traffic rank status.')

    # Feature 27: Google PageRank indicator
    add_feature_detail(features, details, 'Page_Rank', 'Google PageRank', -1, 'PageRank is low or unavailable.')

    # Feature 28: Google Index validation
    if resolved_dns == -1:
        add_feature_detail(features, details, 'Google_Index', 'Google Index Status', -1, 'Domain does not resolve; unlikely to be indexed by Google.')
    else:
        add_feature_detail(features, details, 'Google_Index', 'Google Index Status', 1, 'Domain resolves; assumed indexed by Google search crawler.')

    # Feature 29: Links pointing to page (backlink check mock)
    if resolved_dns == -1:
        add_feature_detail(features, details, 'Links_pointing_to_page', 'Inbound Links Count', -1, 'Domain does not resolve; no inbound links expected.')
    else:
        add_feature_detail(features, details, 'Links_pointing_to_page', 'Inbound Links Count', 1, 'Domain resolves; inbound link profile assumed standard.')

    # Feature 30: Statistical report (known bad keywords search)
    malicious_words = r'paypal-secure|banking-verification|signin-|login-|verify-|secure-'
    if re.search(malicious_words, domain, re.IGNORECASE):
        add_feature_detail(features, details, 'Statistical_report', 'Phishing List Blacklist', -1, 'Matches known phishing pattern in subdomain/domain.')
    else:
        add_feature_detail(features, details, 'Statistical_report', 'Phishing List Blacklist', 1, 'No match on known threat intelligence patterns.')

    # Exactly 30 features matching dataset schema in correct order
    feature_columns = [
        'having_IPhaving_IP_Address', 'URLURL_Length', 'Shortining_Service', 'having_At_Symbol',
        'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain', 'SSLfinal_State',
        'Domain_registeration_length', 'Favicon', 'port', 'HTTPS_token',
        'Request_URL', 'URL_of_Anchor', 'Links_in_tags', 'SFH',
        'Submitting_to_email', 'Abnormal_URL', 'Redirect', 'on_mouseover',
        'RightClick', 'popUpWidnow', 'Iframe', 'age_of_domain',
        'DNSRecord', 'web_traffic', 'Page_Rank', 'Google_Index',
        'Links_pointing_to_page', 'Statistical_report'
    ]

    features_array = []
    for col in feature_columns:
        features_array.append(features[col])

    return {
        'features_array': features_array,
        'features_details': details,
        'resolved_ip': resolved_ip,
        'redirect_count': redirect_count,
        'domain': domain
    }
