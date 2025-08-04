#!/usr/bin/env python3

import argparse
import os.path
import jks
import re
import tempfile
import sys
import base64
from bs4 import BeautifulSoup


# Adjusted the regular expression to be bytes
SECKEY_REGEXP = br"(\d\.\d{2}\.\d{3})\.\d{3}\|(.*)"


# Guess the SID using the fact that property names are formatted
# like this: 'foo/bar/SID = xxxxx'
def get_sid_from_prop(prop):
    with open(prop, 'r', encoding='latin1') as f:
        propnames = [l.split('=')[0] for l in f if '$internal' not in l and not l.startswith('#')]
    sid_candidates = [p.split('/')[-1] for p in propnames]
    try:
        sid = [e for e in sid_candidates if re.match(r'^\w{3}$', e)][0]
    except Exception as e:
        print("SID not properly matched! Our candidates were %s" % sid_candidates)
        sys.exit(-1)
    return sid


# Multi-byte key XOR
def xor(data, key):
    l = len(key)
    return bytearray((
        (data[i] ^ key[i % l]) for i in range(0, len(data))
    ))


# Un-XOR the key from SecStore.key with static secret
def deobfuscate_seckey(secfkey):
    # Read the key file in binary mode
    with open(secfkey, 'rb') as f:
        keyfile_bytes = f.read()
    try:
        match = re.search(SECKEY_REGEXP, keyfile_bytes)
        if not match:
            print("Your key file %s seems broken." % secfkey)
            sys.exit(-1)
        fullver_bytes, key_obfuscated_bytes = match.groups()
        fullver = fullver_bytes.decode('ascii')
    except Exception as e:
        print("Your key file %s seems broken: %s" % (secfkey, str(e)))
        sys.exit(-1)
    ver = True if fullver == '7.00.000' else False
    secret = bytes([0x2b, 0xb6, 0x8f, 0xfa, 0x96, 0xec, 0xb6, 0x10,
                    0x24, 0x47, 0x92, 0x65, 0x17, 0xb0, 0x09, 0xc4,
                    0x3e, 0x0a, 0xd7, 0xbd])
    key_cleared = xor(key_obfuscated_bytes, secret)
    return key_cleared.decode('latin1'), ver


def decprop(secfprop, keyphrase):
    with open(secfprop, 'r', encoding='latin1') as f:
        ciphertext = [l for l in f if '$internal' not in l]
    salt = 16 * b'\x00'
    itr = 0
    plaintextfin = {}
    for i in ciphertext:
        m = re.search(r"(.*?)=(.*)", i)
        if m:
            prop, value = m.groups()
            value = value.replace("\\r\\n", "")
            value_raw = base64.b64decode(value)
            try:
                decrypted = jks.rfc7292.decrypt_PBEWithSHAAnd3KeyTripleDESCBC(
                    value_raw, keyphrase, salt, itr)
                jks_obj = decrypted.decode('latin1').split('|')
                prop_dec_value = jks_obj[2][:int(jks_obj[1])]
                plaintextfin[prop] = prop_dec_value
            except Exception as e:
                print("Error decrypting property %s: %s" % (prop, str(e)))
                continue
    if plaintextfin == {}:
        print("Format unexpected for properties file %s" % secfprop)
        sys.exit(-1)
    return plaintextfin

# Check that SecStore files exist
def check_files(pathkey, pathprop):
    if not os.path.isfile(pathkey) or not os.path.isfile(pathprop):
        print("Cannot find %s or %s" % (pathkey, pathprop))
        sys.exit()


def auto(pathprop, pathkey):
    key, ver_recent = deobfuscate_seckey(pathkey)  # Decrypt KeyPhrase
    print("Keyphrase:", key)
    if ver_recent:  # Decrypt SecStore.properties
        for k, v in decprop(pathprop, key).items():
            print("%s = %s" % (k, v))
    else:  # SID is necessary only in version < 7.00.000
        sid = get_sid_from_prop(pathprop)
        try:
            for k, v in decprop(pathprop, key + sid).items():
                print("%s = %s" % (k, v))
        except Exception as e:
            print('Wrong SID, cannot decrypt %s' % pathprop)


def manual(pathprop, pathkey, param):
    key, ver_recent = deobfuscate_seckey(pathkey)  # Decrypt KeyPhrase
    print("Keyphrase: %s" % key)
    if ver_recent:
        dec = decprop(pathprop, key)
        if param in dec.keys():
            print("%s = %s" % (param, dec[param]))
        else:
            print("There is no %s in %s" % (param, pathprop))
    else:  # SID is necessary only in version < 7.00.000
        sid = get_sid_from_prop(pathprop)
        try:
            dec = decprop(pathprop, key + sid)
            if param in dec.keys():
                print("%s = %s" % (param, dec[param]))
        except Exception as e:
            print('Wrong SID, cannot decrypt %s' % pathprop)


def decodebase64(prop, key):
    prop_f = tempfile.NamedTemporaryFile(delete=False)
    key_f = tempfile.NamedTemporaryFile(delete=False)
    prop_f.write(base64.b64decode(prop))
    key_f.write(base64.b64decode(key))
    prop_f.close()
    key_f.close()
    return prop_f.name, key_f.name


def dec_secStore(prop, key, b64, mode_auto=True, param=None):
    if b64:
        prop, key = decodebase64(prop, key)
    check_files(prop, key)
    if mode_auto:
        auto(prop, key)
    else:
        manual(prop, key, param)

    # data_ciph = '[00|01] XX enc_msg'


def decrypt_DES(data_ciph, keyphrase, salt, itr):
    alphabet_skip = 18
    try:
        data_ciph_bytes = bytes.fromhex(data_ciph)
    except ValueError as e:
        print("Invalid hex data: %s" % str(e))
        sys.exit(-3)
    enc_fmt, enc_msg = data_ciph_bytes[0], data_ciph_bytes[2:]
    if enc_fmt == 0x00:
        return base64.b64decode(enc_msg).decode('latin1')[alphabet_skip:]
    elif enc_fmt == 0x01:
        try:
            dec = jks.rfc7292.decrypt_PBEWithSHAAnd3KeyTripleDESCBC(
                enc_msg, keyphrase, salt, itr).decode('latin1')[alphabet_skip:]
        except jks.util.BadPaddingException:
            print("Bad padding, your encrypted data is probably corrupted or key is wrong")
            sys.exit(-2)
        except jks.util.BadDataLengthException:
            print("Wrong data length")
            sys.exit(-3)
        return dec
    else:
        return "Format of data not understood (should begin with 0x00 or 0x01)"

def dec_data(data, key):
    salt = 16 * b'\x00'
    itr = 0
    return decrypt_DES(data, key, salt, itr)


def get_host_port_from_url(url):
    host_port_re = r'.*://(?P<host>\d+\.\d+\.\d+\.\d+|[A-Z0-9\-\.\_]+)(:(?P<port>\d+))?'
    res = re.match(host_port_re, url, re.IGNORECASE)
    if res:
        res_dict = res.groupdict()
        if not res_dict['port']:
            port = 80
        else:
            port = int(res_dict['port'])
        return res_dict['host'], port
    else:
        return None, None


def print_dest(dest):
    sys.stdout.write("httpdest:Name:%s|" % dest.get('Name', ''))
    dest.pop('Name', None)
    for k, v in dest.items():
        sys.stdout.write("%s:%s|" % (k, v))
    sys.stdout.write("\n")


def parse_xml_blob(data, verbose=False):
    soup = BeautifulSoup(data, "lxml")
    if verbose:
        print(soup.prettify())
        return
    dest = dict()
    # Store final destination
    for p in soup('property'):
        name = p['name']
        if not p.value:
            continue
        else:
            value = p.value.text
        if name in ['Name', 'Password', 'LogonUser', 'URL', 'SAPSystemName', 'LogonBCClient']:
            dest[name] = value
            # Do we have client info? then we can try rfc_*_exec scripts
    required_keys = {'LogonBCClient', 'LogonUser', 'Password', 'URL'}
    if required_keys.issubset(dest.keys()):
        host, port = get_host_port_from_url(dest['URL'])
        print_dest(dest)
        print("rfc_soap_exec.py --host %s --port %s --client %s --user '%s' --password '%s' --cmd info" % (
            host, port, dest['LogonBCClient'], dest['LogonUser'], dest['Password']))
    else:
        print_dest(dest)

    # Main function


if __name__ == '__main__':
    help_desc = ""
    parser = argparse.ArgumentParser(description=help_desc, formatter_class=argparse.RawTextHelpFormatter)
    subparsers = parser.add_subparsers(help="select object for decryption", dest='cmd')

    parser_secStore = subparsers.add_parser('dss', help="decrypt secstore")

    group_secStore = parser_secStore.add_mutually_exclusive_group(required=True)
    group_secStore.add_argument('-a', '--auto', action='store_true',
                                help="Auto-decrypt SecStore.key and SecStore.properties")
    group_secStore.add_argument('-m', '--manual',
                                help="Manual decrypt for a specific resource inside SecStore.properties (ex: jdbc/pool/SID)")
    parser_secStore.add_argument('-b', '--base64', action='store_true',
                                 help="Read SecStore file as base64 encoded input")
    parser_secStore.add_argument('secfiles', metavar='arguments', nargs='*',
                                 default=["SecStore.properties", "SecStore.key"],
                                 help='Custom path to SecStore.properties and SecStore.key (by default open files in working directory)')

    parser_Data = subparsers.add_parser('dd', help="decrypt data")
    parser_Data.add_argument('-k', '--keyphrase', default=None, action="store", help='KeyPhrase to decrypt data', required=False)
    parser_Data.add_argument('-d', '--data', action="store", help='data for decryption in HEX format (ex: 01011c..)',
                             required=True)

    parser_XML = subparsers.add_parser('xml', help="parse XML blob")
    parser_XML.add_argument('-k', '--keyphrase', default=None,
                            help='SAP SecStore keyphrase (decrypted from SecStore.key)', required=True)
    parser_XML.add_argument('-d', '--data', default=None,
                            help='FBLOB extracted from J2EE_CONFIGENTRY (like 01011c[...])', required=True)
    parser_XML.add_argument('-v', '--verbose', action='store_true',
                            help='Show the raw XML output for debugging purpose')

    parser_Test = subparsers.add_parser('test', help="Self-test all decryption modes")

    args = parser.parse_args()

    if args.cmd == 'dss':
        if len(args.secfiles) < 2:
            print("Please provide paths to SecStore.properties and SecStore.key files")
            sys.exit(1)
        dec_secStore(args.secfiles[0], args.secfiles[1], args.base64, args.auto, args.manual)
    elif args.cmd == 'dd':
        decrypted_data = dec_data(args.data, args.keyphrase)
        print(decrypted_data)
    elif args.cmd == 'xml':
        decrypted_data = dec_data(args.data, args.keyphrase)
        parse_xml_blob(decrypted_data, args.verbose)
    elif args.cmd == 'test':
        test_data = {
            "prop": r"C:\Users\admin\PycharmProjects\Training_2\JavaSecStore\SecStore.properties",
            "key": r"C:\Users\admin\PycharmProjects\Training_2\JavaSecStore\SecStore.key",
            "param": "jdbc/pool/PIP",
            "data_key": "asdQWE123",
            "data_msg": "01011CCA381DFB8C834E5CB20604B6BC1F2D191041440C33E2A7BB1C4D82F830AD8387D02517142A1BF6551AD8D0F3F41490B5DBEBC7FA726BE305FE915A1415AA9C388C398C380492734C5B3EC28842DF65F7589365A3EDA3D83710C335285A39562BF3CF45E9BF98A8DBD4F336FEB366427E2F98ED3ADA2242B1E8EA286EDA73C54BEBDC46F484ED51983F5CAC8A88AD595B3B9FBDBD56F11A0B0739C77C9B3EF31F9D616891575804D38B86C8DB9DAA1C00AEF4E76D7608F8F53909741CBA8945FE3F7847B88B09B1DBA4D08E5EEDFEF8E123AEBEFE4EE5157BB66FC7B8B3A0D03F149F527BAAC01696BD7C7A24DF242A5DDE60D475B32EFEAD7C485F679CC7756B4181776E151F7E54B261A422873E314BD18295AB630E84732BC07A5C87C080C6BC65AF2634E5BA10F90A5C6D6AE91D3C00DD327E042CC3FD0DDD1A4410E55FD3A0748A4A4B2DA26BF9D371ED0A7A49545F4E73FFC117FDEB278CB98902488C49D02861B33F728213DA65E858517778D6437EF5E7443C3CE94965B5ED1BB494DDF876F02746CE91CEB59330020A996401BA62A4D900DF4870AF32F1359E9E814A6381CF302A583525ED41B34072F5C553EA2D7162B10E77BD0A49F8590CF1EFE1D2FBA9744F92D6F49111933418D7027BCB9588D997794D003FEC6F9B9C0C302D50F02E7EB8A615107F322CEC28E5428244AD90925E1FCCBEEAA1F067FC185B599F003EF47D97BF7713E2C53AA80436AB1665C38B83CE853D2D9D7E7AE6E8F78EF279C824315566724C1F1ED8D02FAA4A619D58971BB0B4D26A24D5E1703A4B607FAF2D2A5E8CCB86657D0D100607A7211D7CB1622114C90E9D2BA09DFFD9AAFE8CEF7851021E53C67D4E800B93623195CCD60EDCA52F1E3162401843A7D39DAFEF643BBB77FC2A5B53670A6B369D6420C9DA9AB6D2EBB651AFCCF01A4E186F8CF1E33E14D32300472A11173BB1D6D32261D5EAAC78CB3C56219F73E5DA97A80DC99AFA4B8B28B1A9CBC01AF6A55355523BC42DBE384C8A69C3C3E6EA1BD4762588B241D12BEAC7C0790C48423D3AAF1A8783D1E85E77DF1C24EAECCD0ED1A39C97147390D1785EA34FE69BDDB7131DC8EBE6848D4D218F54A60368FA9C0D4B3A3EFCAC58FB6159FA1B8750F319484DC200EF6CA226AB7C40DEA7C052E9C93F049EA16243ABB415609759BD8E6BD065A4CD1095FDC8A5C92B2287B507ED7BFF8CA12B6E6AE514E4E080A2D361B89020B3B4E6351B50ABF1941025623650ED1DF6FE2A81C7E11962A411B78CB0126E51C4D0FCFBD4146BD0AAED0987199EC4883858B45969E01B0943BCB8B3BCB1A4AC8E92898E9CA4A38CF798A8BCE33E42B78C9B732B047BAB21C4DBB9376B62AB5EE4F5DABFF5E1B392396DB397E4F667A7CB1BADFFA623F95479BA39257F730B9DA3CF2D7FCF408046A6E910D0204C9EC4290760855D8B906A46E5C3FA6A7470085E75586EE4264CCA8FE5004773A1CA339DB7E473C7E52A9FA3495D96DE75C8A549917A143A109EC57EEB108B5F828AA6D47391B2DE76438D6E63BEBEFA0D9F626F680AAA499EED6E895E73A547ED3CAF69E4B82DFA4B46F180ACFF8D3EDA0B605BABE710F254D1878F92CBA13C4B02F915FD6AE4787C5BDEFF4A91256DBF51512DCA1D0FBFCD7B16C8A766B357674848A331F00496A3C8F554C66438B58E3862B878975B63E5CE836140691C3F42275EE32AA6E4AC284B6716AE4DADE23D8A375D26B1B4F35B4AF46329BF10F17B655DC143DA53122027EF25E26336AACE2527F32AFC9AF32B665AE78C7D04925750E2ADB3D1363F48F9ABE5CD1E0C36A9097E08F7160E843FD2D2F80B1D4F4BA290AE7CFB34EDBFFC29AC42B987E1FBF98EC18FA8246B07B078E13C8CCE5A5A003C4396E0DB8FB08622DDCC1199B98A88BF7CC2C1A31D86A85E7F0B3AC40304F8BFAFCDC5A5009CBDC4EB2FC17E7DFC8781BFC83E61C9B666DE7E29108208000F5A131A1CDFEEBE5AE5B7ED63B3D090C846284071B73DB754D14C46C473B4B4499F3FECD71F8F19A5E9AEF052047D1C9539EB508A8C3AE343ECC0263B47892ADD2A6364ED65322450FF3D0C068D4AA4293999A5DEDFBAB2842898BA1277B130FB1B4A6F240DB1D0CF2E9FB5C7A1240D07E6627D4E6EE8B48F4AAFCBCDC1F8D0809ADD71DDE4F5DF1FB1A2F355BCD20DEEBB2D26EBC96970F089F54221EACB83157367FFAAE11A884A950E3883EB5F544312D46AB6D1E0CE402D7DF322AA60E2D2F537022987D6DD2E92EFAD5160CE91A686C1BB6DA45CC7BCC3BB7901C2E3008196C0963FFB91254A7BC96F21E1F81DDFCA930BDD4D46D1D02A1EFD969F9C77B786CA47BA22695A68EB7F37302EBECF1498978DE453790B2A36D634122DDDACD5FD4CE7D68B5BDA81030A0EFF2AEF26D4B7820E41E2D680C5FBB7D54F4FF4EA29988E7FE733A81411FBAEF847740DA576377E3FCA635CECD592428E2475A887BADEBD1E93EBB96FD91FB37E05988C2D9AFD1B04FCB2CDC0359B3015B4E4A4263BAA24611DBFFD668091E978DA0F127CD1D93D7AB07FD10572291FFAF1355FA7BDBA2504C120ED3E6ADDB91072DC28764D6F040986FE18E1AA12AC4A86B57D9058F9EEC00FA9543134D423F1B55770F7EE1039904B923BA77C9AC1EB9079727C6C3165EE31C39883EABC2489F436242CBA8EFF96FB5C7A09743366F6BC967ACD702B0A7F3B7BCD50AF9C46E57129A7961420C53A8706F1652C865E5B91BCF4B290AABD4B40A2005F986D2387796132C60AF71018D8BAB442F704B4637105F131407AC0D06E0F4A0B20FA55AF2878182DD19932724FD6B8C78439C828D8BE3FB245CC980B3F0493447EC1CEF3560280853D0BE03B179FAEFFE257623224456AE231C546F43C2B6766269E7ACE051D6DF5723C24B477284F765E2C4D72F97D23BFA604583C74D51A234C6D9026C8C8D91BCB30F5E15BDC8F74C498DA9C62B57C5D33691E1622561B1EDB332F52CE87700D71B235390A02BA2C0B605628599C096147DD9775A30A7F0BD8EFD64E9B4BFDAD9F5387D3144961A7A238F1373037D6C3E323DADCB7514802A3B583DCA460FC1E194CD59214029BDD27C7E375E244528B3AAA19718A83B1F353CD8371D2AEAEF4AC5582E2779568EC54D5486F3E87FBFB2666706FA4533F376A2EC06AE6F7CC710DD2E351EDC21B52834CB8BF2E1F39E2694328333C3A372BB8EEBB32EAAEDFD553BA2336DFD9307BA6D7BD036F08A324B3195938099BEEDCFB9CE7BFB433EB8920153474F918CEA1102A4FCCEC5A80C85675A39EEE16EF7CCCF715E37A3D731E0EC05F0C72279CFC5A20230BC0888F5E9B275D5B99D7015285BA5ED8FDFBB9CEDEC9A67F79A4C2B89FC8CD24B67685D0DABA417E7FE5DCFFCD99CC133B410D5DF6175F72A57A4501C8282C963DED9A9DB4FCA6F2C09EB0D50259299DEA3D3895371507AF64245E5AE0669C70419FF7D84F940FBBB773E509659C97FC0AB987BFC5D483DB7207C08DCB9E7A8EDD81DC8C5B28F98CB95ABAA1E55F5E93E12D40C02B847795E9AFD08A842054A706A33F907BA9EBB8CCC2E3357141515ACA4ACD59EC7CD4E7C7EFC760EBF3379F94A1C0897AED722E2C714713E53030D66FB25177116CA324D407FFAF9DD3DEAC6F3E6353FD5E3BD6C89886F32B68D8A61BB44B8593F1DF7034F878E2B06E87F97B66ED07C332E35D40DA969B545DB443F5B813735057CB1E772569A3DDAD021E21AC62FF84D19C02475C65DF2660E42159E246082D4C2A5FADB77010B671BC2FE793B8A0B80C9A36A2411D7B1058FF1B7161A41F4FDBD65DAF7970E0A4DD8AB4E7FDF13FBB40D1E886AF18BB1FA48CBB7564FC82BB01C87BCBF6F9755D02C529430944B3A86F3B7B999A8C153473A9A818112505D8C8548A8BDA061539D337CDB4EBEA5B9358318B1EB703D834B6AA53B548305E2726D5AE39957C374ED49D696E4EB9F4DBF12892A86E4731B75BF8D8808C1B1B9515BF684BD8C212328EC1EDB3D8605D30AE11CB7D26D08418E14216F03A19C4662E66938D16AD4792379351B94F387BBE30463226F0DFE7B4165BBC421B7A585410D45405A9105FB4770173AA7F067539D08EB4742F7EACF6E05BD76A37711F010EF87BA59272A1E981DE3FB41200518EEC4A6CB795F9F605900FDC6831873FA253776DE4AF9B14ADF81B80F87E92E3C134D318F4595CF92FF972040667DF209766583FA8E37BD18419E526CDC46E4CBD73EE2DB1A68B3B74F1D0F307C5AC066321DA1A67DD71F613287D3767E6E6EBE554678242E356272A9D287268454BB3B169739986DE05862BFD2ACC00FA7CAC6611AE81F982A94195CE459B972EEE85DF9A124981F33A3E7386717C654ADF367FEF49A5427BB34FA4C9B4D5E65C2C850EC3776E02A4FC42E49781164D21C407FCE4FAC356754EAF2E94A3B4CDC4415C53BED87691F45769134148380FEAF3FBF57163FC96902C403605FF8F655CE6642EEC2819A705DDB0D6FE70E28E667B36BF88F9342EA7D05571AFF1397DB49AA33DD50EC7C3CDB844E4B7294000314A9180039CCEFCFF61625368C78D9C97E9314F81B07F1A7D20CABEC0E31BCA076FE77B61933D87E67773717A66EEE529244203B8EC609D5725D2767FF1441359EE1A5F758F07CDAB33A8A31CA1A9FC2A080415B8523C62C1361B5389C03E16EFB59509A60A8E5A202472ED9E477ED536E904F0C99B86D3757513DF64F26BE442EF56CBCE71CF3A9AAE35799953E2DA172A8A4B27949C4B674A8AF022AD03A5236E5AEFDE0E6B8EAE7B6A40F04F3900A22D3F9DBFA9C2457317EDC18163BACF4E4B2F24123D1804923E97FFF9D27E49B178587F6CC2ECAB907C72A5CBC2D66BEC01169C4C1DCDA82872956DD3DDC03A2D3DC77CE2C4D8C8C25F654FE76BF040D3CA784D5ACD3CF40DC762CAB7D86B8B0269A7ED3E9F697D6A55A787CE0B37D97753AA43D27124A1055E4B9DFA2ED42FA0BDA0234A329894948CF65BE68170A7201B55D3F8442D8CCB8956DEE221D35E3BA477BA81029228C8AD3F11A0D1C05BE2AB7138F5055E67C8FCD872F415922D62527DA78FE5758ECFBEC798ADDCF5DFCD1689B7FCF2A4B7E7821C78FB47D7F79349F1355A365CA74EF3A249FB00DA3E6C600DED78B6970500FC43510B2CC2A54D834C51A9A8B79C40A01419DAD06F870D3FA68F4EC0770F9F99204025A85C59C684B42C192B594B889E8096D5154EA386225526AAE2FC8C620ECC380F9C84493C6A6EE1161583D72FC35371EA754EC3EEBEF6CD9908361FF2D8F468F2FFEBD9550BBB6DC4D59611DC387104BEC066C43DA599D8554BD528BB3088EEEEC7622D5D292ECE1629B9139245548E448778EEA0B4750D65C67E062481DA18069A704F06C8A7F6D3629F3247F15F8DDF47C68D60F9126E730BA593FD7F84EEE603677DC9F41B74059AC2DC045D6001FF7F0184210FE7A8C93E67419450560BF3635EF364577612CD53D4205A2A2B0C99489372933E5CE9973E6720517A4EEF692375FF7105B2CF33999B80580888F0276ED0B2C428E34D863585418A163AE46E89D06CAA142D3F44ECE0F0E44AB71E05AC7D1CF341E3F5014E5951F1D37B2F258AD0B4291137E6E0E77EB9BE0B9284E45C2D1288EF2274AA0DD7A81E4F4DD81266399015F19E8B23818ADDAB789498D1F5781F4078E354BFEDC638B807ABF9527D6A039B9DC22CCBAD1AE34F694E20E3FCE85E8C6A2E4D67902161A693F7D48E85EEAD2C87F663F46D3F965D6396A0AC748008A783B8BC10AF1F7AEF2AD0AF82E8D84311F142E21B4108A9266FB27BA26BC5A2B6F086D6087F83EAD37C28487B5C1334A51BAC094743B600B51713BB61F55DC0698E5B56C2EA3319AC4C3B129BFCED4E677E99D760B147F275BCA14FA9BCAA9269B0ACF9879344EE4235F7C63B11EB965E10BBEFA53A9290196BC7F80036DBF7023276D1E20171DA4FFFF0F2F108C12C21DFA77A805197E6D46AAB502104067169D0139D627E32DB954D38A4DE1489CAC152F031EB1FCB079E10ACA4A512AAA79B44892ED0A299F0F29B6EA69620FDEFE07DF5891D0C59B42FE630D9B3872D248429E5E4EEB15BC22A21452B460E8A547725CAE4BB5AC6B731EE558F05403B0E90CEC78AC80F7E358856E341B6D5EE4C7D83A632BD1A5D5747CD2B74F9875B2E576128587D6C457DE9C69BDE9372012615C3595E494B5E34F344E2AF4D2B0FAD02A88007F15D2821829D078E5A142D87EBE952BD1DFBA9A8E5B92ADE2F50BA8FA347EC339B3085557A9029516B4489926D7F571D6A996E7FE8698CAED40AE38AD6470D62FB3145B8B8FE6110A836AA695036F1A4BD8462C9F897815984BE2B42F1C9E212AB770CE11DF20A076F01DDF52E0DFD4144676AB1D6AE8E0F8F1EFEC60B3675D8F5FFD76D7A1C0F998137E3D7318D3BB772D7E51469E206CFCFC0C3261AE3F862AB0C11497F8BEE96A239D4F8EAD9A465E9C120C56C4684912C5E76D474DB2CC486ECBE2E287A6E4C08A8A9EA1FCFB86324C186A3FE86297E95829372D69F3DBE27796CD19C30515F1DB5B54F2683410DDE1FFD2AD25ED9DD0DCA3D616763D273028D9A9BE68B174EB7A126661E3BD084AE5D9EAF000FFC16455AFB8EC9EA69151415F4B2B347A2E92A0AF7644F3DD7C5AFA115AFFD2A5F64C94E344ECEBC31BA939126170559F24DCD6342C2106E3D3E9912CBF05A502E64B0470EB4DAC980842E2E81530AFD6BF47E9E16E7C8150726214BBEC04CBD0E6E240D8D5A8F38C81541188AF3E9E8C9FE77807020F1715BAE0DD335F4AF1BCFB1DDBE420FB91D38901E22494026B3129CC067A1BE53A01995119AC37EB19B7EF5DBFEA9047CFAA3A7819590CD72AB7EDB0564B4860CD92ACF1DD64CA03EBC17D01E3C42F14169F9C4C1078E091C74D6DB9AA6A1BB0425D8EBD877"
        }
        #print("[+] Auto decryption of %s with keyfile %s" % (test_data['prop'], test_data['key']))
        #dec_secStore(test_data['prop'], test_data['key'], False, True)
        #print("\n[+] Manual decryption of param %s for propfile %s" % (test_data['param'], test_data['prop']))
        #dec_secStore(test_data['prop'], test_data['key'],
        #             False, mode_auto=False, param=test_data['param'])
        #print("\n[+] Decryption of DB encrypted data 'asdQWE123'")
        print(dec_data(test_data['data_msg'], test_data['data_key']))
    else:
        parser.print_help()
