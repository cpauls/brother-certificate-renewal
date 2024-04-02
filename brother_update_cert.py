'''
Description: Auto renew certificate for Brother Printer. Tested for MFC-L3750CDW 
Date: September 17, 2023
Author: @davidlebr1
'''

import requests
import urllib3
import argparse
from requests_html import HTMLSession

# Remove insecure warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Global Variable
protocol = "https"  # http or https
hostname = ""  # hostname or ip of your printer
certificate = ""  # Certificate path
password = ""  # Admin password login
certPassword = "" # password for certifcate
session = HTMLSession()


def authenticate():
    # Get CSRF token from login
    response = session.get("{}://{}/general/status.html".format(protocol, hostname), verify=False)

    # Authenticate
    paramsPost = {"B12a1": password, "loginurl": "/general/status.html"}
    response = session.post("{}://{}/general/status.html".format(protocol, hostname), data=paramsPost, verify=False)

    check_login = response.html.xpath('/html/body/div/div/div[1]/div/div/div[3]/ul/li[3]/ul/li/a')
    if check_login:
        print("[*] Login Successful")
    else:
        print("[*] Couldn't login")


def deleteCert():
    # Delete last Cert
    # Get idx cert
    idx = 0
    response = session.get("{}://{}/net/security/certificate/certificate.html".format(protocol, hostname), verify=False)
    links = response.html.links
    for link in links:
        if "view.html?idx=" in link:
            idx = link.split("=")[1]
            break

    # Get CSRF from delete page
    response = session.get("{}://{}/net/security/certificate/delete.html?idx={}".format(protocol, hostname, idx),
                           verify=False)
    token = response.html.xpath('/html/body/div/div/div[2]/div[2]/div[2]/div/div/div[2]/form/div[2]/input')[0].attrs[
        'value']

    # Delete cert
    paramsPost = {
        "hidden_certificate_process_control": "1",
        "CSRFToken": token,
        "hidden_certificate_idx": idx,
        "B12b2": "",
        "B12c4": "",
        "pageid": "381"
    }
    headers = {
        "Accept": "*/*",
        "Content-Type": "application/x-www-form-urlencoded",
        "DNT": "1",
        "Origin": "{}://{}".format(protocol, hostname),
        "Referer": "{}://{}/net/security/certificate/delete.html?idx={}".format(protocol, hostname, idx),
    }

    response = session.post("{}://{}/net/security/certificate/delete.html".format(protocol, hostname), data=paramsPost,
                            headers=headers)
    token = response.html.xpath('/html/body/div/div/div[2]/div[2]/div[2]/div/div/div[2]/form/div[2]/input')[0].attrs[
        'value']
    paramsPost = {
        "hidden_certificate_process_control": "2",
        "CSRFToken": token,
        "hidden_certificate_idx": idx,
        "B12b2": "",
        "B12b3": "",
        "pageid": "381"
    }
    headers = {
        "Accept": "*/*",
        "Content-Type": "application/x-www-form-urlencoded",
        "DNT": "1",
        "Origin": "{}://{}".format(protocol, hostname),
        "Referer": "{}://{}/net/security/certificate/delete.html".format(protocol, hostname),
    }
    session.post("{}://{}/net/security/certificate/delete.html".format(protocol, hostname), data=paramsPost,
                 headers=headers)

    if idx != 0:
        # Check if cert was deleted
        response = session.get("{}://{}/net/security/certificate/delete.html?idx={}".format(protocol, hostname, idx),
                               verify=False)
        is_deleted = response.html.xpath('/html/body/div/div/div[2]/div[2]/div[2]/div/div/div[2]/form/div[3]/p')
        if is_deleted:
            print("[*] The certificate has been successfully deleted")
        else:
            print("[*] The certificate has not been deleted")
    else:
        print("[*] There is no certificate to delete")


def uploadCert():
    # Upload cert
    # Get CSRF token to submit new cert
    response = session.get("{}://{}/net/security/certificate/import.html?pageid=387".format(protocol, hostname),
                           verify=False)
    token = response.html.xpath('/html/body/div/div/div[1]/div/div/div[1]/div[1]/div/div/form/div/input[1]')[0].attrs[
        'value']

    headers = {"Origin": "{}://{}".format(protocol, hostname),
               "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
               "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:98.0) Gecko/20100101 Firefox/98.0",
               "Referer": "{}://{}/net/security/certificate/import.html?pageid=387".format(protocol, hostname),
               "Connection": "close", "Sec-Fetch-Dest": "document", "Sec-Fetch-Site": "same-origin",
               "Accept-Encoding": "gzip, deflate", "Dnt": "1", "Sec-Fetch-Mode": "navigate", "Te": "trailers",
               "Upgrade-Insecure-Requests": "1", "Sec-Gpc": "1", "Sec-Fetch-User": "?1",
               "Accept-Language": "en-CA,en-US;q=0.7,en;q=0.3"}
    paramsPost = {"hidden_certificate_process_control": "1", "CSRFToken": token, "hidden_cert_import_password": certPassword,
                  "B12b2": "", "B12c0": "", "B11b1": certPassword, "pageid": "388"}
    # paramsMultipart = [('B11b0', ('brother.pfx', open(certificate, 'rb'), 'application/x-pkcs12'))]
    paramsMultipart = {"B11b0": open(certificate, 'rb')}
    response = session.post("{}://{}/net/security/certificate/import.html".format(protocol, hostname), data=paramsPost,
                            files=paramsMultipart, headers=headers, allow_redirects=True, verify=False)
    error = response.html.find('div', containing='rejected')
    if error:
        print("[*] An error occured in the upload")
    else:
        print("[*] The certificate has been Successfully uploaded")


def selectCert():
    # Select certificate in HTTP Server Settings
    # Get CSRF Token
    response = session.get("{}://{}/net/net/certificate/http.html".format(protocol, hostname), verify=False)
    token = response.html.xpath('/html/body/div/div/div[2]/div[2]/div[2]/div/div/div[2]/form/div[2]/input')[0].attrs[
        'value']

    headers = {
        "Accept": "*/*",
        "Content-Type": "application/x-www-form-urlencoded",
        "DNT": "1",
        "Origin": "{}://{}".format(protocol, hostname),
        "Referer": "{}://{}/net/net/certificate/http.html".format(protocol, hostname),
    }
    # Get the Cert from dropdown
    cert_dropdown_id = \
        response.html.xpath(
            '/html/body/div/div/div[2]/div[2]/div[2]/div/div/div[2]/form/div[4]/dl[1]/dd/select/option[2]')[
            0].attrs['value']

    # Post the selected cert to use it
    paramsPost = {"pageid": "326",
                  "CSRFToken": token,
                  "B12c8": "",  # hidden
                  "B12cb": cert_dropdown_id,  # selected cert id
                  "B12c9": "",  # hidden
                  "B11fc": "1",  # webased management https 443
                  # "B11fd": 1,   	    	 # webbased management http 80
                  "B120e": "1",  # ipp https 443
                  # "ipp_ssl_used": "on"  ,
                  # "B120f": 1,  	    	 # ipp http port 80
                  # "B1210": 1,  	    	 # ipp http port 631
                  # "B11ed": 1,  	    	 # webdienst http
                  "B12e5": "1",  # hidden button
                  "http_page_mode": "1"  # hidden
                  }
    response = session.post("{}://{}/net/net/certificate/http.html".format(protocol, hostname),
                            data=paramsPost,
                            headers=headers,
                            allow_redirects=True,
                            verify=False)
    error = response.html.find('div', containing='rejected')
    if error:
        print("[*] An error occured during selecting cert.")
    else:
        print("[*] Selected cert with id {}. Will restart...".format(cert_dropdown_id))

    # restart
    token = response.html.xpath('/html/body/div/div/div[2]/div[2]/div[2]/div/div/div[2]/form/div[2]/input')[0].attrs[
        'value']
    paramsPost = {
        "pageid": "326",
        "CSRFToken": token,
        "active_other_protocol": "1",
        "http_page_mode": "4"
    }
    response = session.post("{}://{}/net/net/certificate/http.html".format(protocol, hostname),
                            data=paramsPost,
                            headers=headers,
                            allow_redirects=True,
                            verify=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("hostname", help="Hostname or IP. Without http://. ", type=str)
    parser.add_argument("certificate", help="Full path of the certificate (.pfx file).", type=str)
    parser.add_argument("password", help="Administrator login password", type=str)
    parser.add_argument("-p", "--protocol", dest="protocol", help="Protocol: HTTP or HTTPS. By default it's https ",
                        default="https", type=str)
    parser.add_argument("-cP", "--certPassword", dest="certPassword", help="Password for certificate. By default it's empty '' ",
                                                default="", type=str)

    args = parser.parse_args()

    protocol = args.protocol
    hostname = args.hostname
    password = args.password
    certificate = args.certificate
    certPassword = args.certPassword

    authenticate()
    deleteCert()
    uploadCert()
    selectCert()
