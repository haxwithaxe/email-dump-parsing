""" Parse a bunch of raw email files to produce a list of easier to use Message objects.

Usage:
   ```
   python3 -i <this script>
   >>> messages = walk_dump(<path to dump directory>)
   ```
   
"""
from datetime import datetime as dt
import email.parser
import glob
import pickle
import re
import urllib.parse


DATE_HEADERS = [
    'Delivery-Date',
    'Date',
    'Expires',
    'Expiry-Date',
    'Reply-By',
]

AUTH_RESULTS_HEADERS = [
    'Received-SPF',
    'Authentication-Results',
    'ARC-Authentication-Results',
]


def dump_message_metadata(msg):
    """Dump a greppable metadata file next to the original.

    Keys are followed by ">>>" to flag it as a field key.
    """
    with open(msg.filename+'.metadata', 'w') as metadata:
        metadata.write(format_metadata('content_type', msg.content_type))
        metadata.write(format_metadata('is_multipart', msg.mail.is_multipart()))
        for key, value in msg.headers.items():
            metadata.write(format_metadata(key, value))


def pickle_message(msg):
    pickle.dump(msg, open(msg.filename+'.pickle', 'wb'))


def format_metadata(key, value):
    return '{}>>>{}\n'.format(key, urllib.parse.quote(str(value).encode('utf-8')))


def walk_dump(dump_path, dump_metadata=False, dump_pickle=False):
    """Iterate over the files in the dump directory and turn them into Message objects.
    
    Note:
        Don't use the `dump_metadata` or `dump_pickle` and run this function again. It will contaminate `dump_path` with nonemail files.
    
    Arguments:
        dump_path (str): The directory containing the email files.
        dump_metadata (bool): If True a grepable metadata will be written to `*.metadata` alongside the email file.
        dump_pickle (bool): If True a pickled `Module` will be written to `*.pickle` alongside the email file.
        
    Returns:
        list: A list of `Message` objects for each files in `dump_path`.

    """
    filenames = glob.glob(dump_path+'/*')
    messages = []
    for filename in filenames:
        msg = Message(filename)
        messages.append(msg)
        if dump_metadata:
            dump_message_metadata(msg)
        if dump_pickle:
            pickle_message(msg)
    return messages


def date_header(value):
    """Make dates into datetime objects."""
    date_tuple = email.utils.parsedate_tz(str(value))
    if date_tuple:
        value = dt.fromtimestamp(email.utils.mktime_tz(date_tuple))
    return value


def parse_authentication_results(value):
    """Make a dict of https://tools.ietf.org/html/rfc5451 parts."""
    parsed = {
        'authserv-id': None,
        'version': None,
        'passed': None,
        'properties': None,
        'notes': None
    }
    match = re.search(
        r'\s*([\w.-_]+)\s*;(?:\s*([\w._-])\s*;)?\s*(\w+)=([\w!$&*=\^`|~#%‘+/?_{}-]+)\s*(\([\W\S!$&*=\^`|~#%‘+/?_{}-]+\))\s*(.*)',  # pylint: disable=line-too-long
        str(value)
    )
    if not match:
        return parsed
    authserv_id, version, auth_method, result, notes, properties = match.groups()  # pylint: disable=line-too-long
    parsed['authserv-id'] = authserv_id
    parsed['version'] = version
    parsed['auth_method'] = {
        auth_method: result == 'pass' if result != '' else None
    }
    parsed['notes'] = notes or None
    parsed['properties'] = dict(
        re.findall(r'([\w_.-]+)=([\W\S]+)\s+', properties)
    )
    return parsed


def parse_addresses(field):
    addresses = []
    if not field:
        return addresses
    for address in str(field).split(','):
        match = re.search(
            r'''(.*?)[<"']?([\w!$&*=\^`|~#%‘+/?_{}-]+@[\w_.-]+)[>"']?.*''',
            address
        )
        if match:
            label, addr = match.groups()
            addr = addr.lower()
        else:
            label, addr = None, None
        addresses.append(Address(label, addr, address))
    return addresses


def decode_headers(headers):
    """Get rid of email encoding in headers."""
    decoded_headers = {}
    for key, value in headers:
        if isinstance(value, (str, bytes)):
            value = email.header.make_header(
                email.header.decode_header(value)
            )
        if key in DATE_HEADERS:
            value = date_header(value)
        if key in AUTH_RESULTS_HEADERS:
            value = parse_authentication_results(value)
        decoded_headers[key] = value
    return decoded_headers


class Address:
    """EMail address model.

    | label       | address           |
    |Alice Alisson <alice@example.com>|

    Attributes:
        label (str): The "label" part of the address.
        address (str): The "address" part of the address.
        original (str): The original string.

    """

    def __init__(self, label, address, original):
        self.label = label
        self.address = address
        self.original = original

    def __repr__(self):
        return '<Address label={}, address={}, original={}>'.format(self.label, self.address, self.original)


class MessagePart:
    """Message part of a multipart message model.

    Attributes:
        isattachment (bool): True if this part is an attachment.
        ishtml (bool): True if 'text/html' is in `self.mime_type`.
        mime_type (str): Message part mime-type.
        disposition (str): Message part disposition.
        part (email.Message): Message part object.

    """

    def __init__(self, mime_type, disposition, part):
        self.isattachment = 'attachment' in disposition
        self.ishtml = 'text/html' in mime_type
        self.mime_type = mime_type
        self.disposition = disposition
        self.part = part


class Message:
    """EMail message model.

    Attributes:
        filename (str): The name of the source file.
        mail (email.parser.BytesParser): Parsed object from `email`.
        body (str): Decoded email body.
        headers (dict): All the available headers decoded and in some cases parsed more.
        subject (str): Subject header.
        to_ (list): To header as a list of Address objects.
        from_ (list): From header as a list of Address objects.
        cc (list): CC header as a list of Address objects.
        bcc (list): BCC header as a list of Address objects.
        authentication_results (dict): Authentication-Results header parsed into usefull bits.
        content_type (str): Message content type according to `self.mail.get_content_type()`
        parts (list): A list of MessagePart objects based on the multiple parts of a multi-part message.

    """

    def __init__(self, filename):
        self.filename = filename
        with open(filename, 'rb') as msg_file:
            self.mail = email.parser.BytesParser().parse(msg_file)
        self.body = self.mail.get_payload(decode=True)
        self.headers = decode_headers(self.mail.items())
        self.subject = str(self.headers.get('Subject'))
        self.to_ = parse_addresses(self.headers.get('To'))
        self.from_ = parse_addresses(self.headers.get('From'))
        self.cc = parse_addresses(self.headers.get('CC'))  # pylint: disable=invalid-name
        self.bcc = parse_addresses(self.headers.get('BCC'))
        self.authentication_results = self.headers.get('Authentication-Results')
        self.content_type = self.mail.get_content_type()
        self.parts = []
        if self.mail.is_multipart():
            for part in self.mail.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get('Content-Disposition'))
                if (content_type == 'text/plain' and
                        'attachment' not in content_disposition):
                    part = part.get_payload(decode=True)
                self.parts.append(MessagePart(
                    content_type,
                    content_disposition,
                    part
                ))
