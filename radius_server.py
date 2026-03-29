import socket
import hashlib
from typing import Any, List


# ===============================================================================================================
#                                              Global Constants
# ===============================================================================================================
HOST = "0.0.0.0"
PORT = 1812
shared_secret = b"my_secret_key"


# ===============================================================================================================
#                                              Helper Functions
# ===============================================================================================================
def parse_header_info(packet_data: bytes) -> dict[str, Any]:
    """
    Parse the RADIUS packet header.

    Parameters:
    packet_data (bytes): The raw RADIUS packet bytes.

    Returns:
    dict[str, Any]: Dictionary containing:
        - code (int): RADIUS packet code.
        - identifier (int): Packet identifier.
        - length (int): Total packet length.
        - authenticator (bytes): 16-bytes authenticator value.
    """
    header_info = {
        "code": packet_data[0],
        "identifier": packet_data[1],
        "length": int.from_bytes(packet_data[2:4], byteorder="big"),
        "authenticator": packet_data[4:20],
    }

    return header_info


def parse_attribute_info(attribute_data: bytes) -> dict[str, Any]:
    """
    Parse a single RADIUS attribute.

    Paramters:
    attribute_data (bytes): Raw bytes of the attributes starting with type, length and value.

    Returns:
    dict[str, Any]: Dictionary containing:
        - type (int): Attribute type.
        - length (int): Length of the attribute including type and length bytes.
        - value (bytes): Attribute value bytes.
    """
    attribute_info = {
        "type": attribute_data[0],
        "length": attribute_data[1],
        "value": attribute_data[2 : attribute_data[1]],
    }

    return attribute_info


def parse_all_attributes(attribute_data: bytes) -> List[dict[str, Any]]:
    """
    Parse all RADIUS attributes from the packet payload.

    Parameters:
    attribute_data (bytes): Raw bytes containing multiple RADIUS attributes.

    Returns:
    List[dict[str, Any]]: List of attribute dictionaries as returned by parse_attribute_info.
    """
    parsed_attributes = []

    current_pos = 0
    total_length = len(attribute_data)

    while current_pos < total_length:
        remaining_bytes = attribute_data[current_pos:]
        attr_dict = parse_attribute_info(remaining_bytes)
        parsed_attributes.append(attr_dict)

        current_pos += attr_dict["length"]

    return parsed_attributes


def get_user_info(
    attribute_data_dictionaries: List[dict[str, Any]], type_code: int
) -> bytes:
    """
    Retrieve the value of a specific attribute type from parsed attributes.

    Parameters:
    attribute_data_dictionaries (List[dict]): List of parsed attribute dictionaries.
    type_code (int): The RADIUS attribute type to retrieve (e.g., 1 = username, 2 = password).

    Returns:
    bytes: Value of the attribute if found, else empty bytes.
    """
    for d in attribute_data_dictionaries:
        if d["type"] == type_code:
            return d["value"]
        else:
            continue

    return b""


def decrypt_password(encrypted_password: bytes, shared_secret: bytes, authenticator: bytes) -> str:
    """
    Decrypt the RADIUS encrypted password using the MD5 key.

    Parameters:
    encrypted_password (bytes): The password bytes received from the RADIUS request.
    shared_secret (bytes): A shared secret between the server and user.
    authenticator (bytes):

    Returns:
    str: Decrypted password as UTF-8 string with null padding removed.
    """
    result = []
    previous_chunk = authenticator

    for c in range(0, len(encrypted_password), 16):
        chunk = encrypted_password[c:c+16]
        key = hashlib.md5(shared_secret + previous_chunk).digest()
       
        for byte, k in zip(chunk, key):
            curr_decrypted = byte ^ k
            result.append(curr_decrypted)
        previous_chunk = chunk
    decrypted_result = bytes(result).decode("utf-8")

    # Remove the training null padding
    return decrypted_result.rstrip("\x00")


# ===============================================================================================================
#                                              Main Function
# ===============================================================================================================
# Get host IP address dynamically
# curr_host = socket.gethostbyname(socket.gethostname())


"""
AF_INET and AF_INET6: Specifies what kind of IP address format the socket will use.
                      AF_INET uses IPv4 addresses.
                      AF_INET6 will use IPv6 addresses.

SOCK_DGRAM, SOCK_STREAM: Specifies what kind of communication behvaior the socket will use.
                      SOCK_STREAM provide a reliave, connection-oriented byte stream (typically TCP).
                      SOCK_DGRAM provide connectionless datagram communication (typically UDP).

"""


def main():
    # Creating the UDP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Bind it to RADIUS authentication port
    server_socket.bind((HOST, PORT))

    print("Listening for RADIUS Access-Requests on UDP port 1812...")

    while True:
        # recvfrom returns a tuple (the raw bytes, the sender's IP and Port)
        packet_data, nas_address = server_socket.recvfrom(4096)

        # Getting header info of the recived packet
        packet_info = parse_header_info(packet_data)

        # Verify the packet is an Access-Request
        if packet_info["code"] == 1:
            print("We recieved an Access-Requests")

            # Retriving the attributes (Ignoring the 20-bytes header info)
            attribute_data = packet_data[20:]

            # A list of parsed attribute dictionaries
            parsed_attributes = parse_all_attributes(attribute_data)

            # Retrive Username
            username = get_user_info(parsed_attributes, 1)
            username = username.decode("utf-8")

            # Retrive Password
            encrypted_password = get_user_info(parsed_attributes, 2)

            # Constructing the key MD5(shared_secret + authenticator)
            key = hashlib.md5(shared_secret + packet_info["authenticator"]).digest()

            # Decrypted Password
            decrypted_password = decrypt_password(encrypted_password, shared_secret, packet_info['authenticator'])

        print(f"Recieved {len(packet_data)} bytes from {nas_address}")


# ===============================================================================================================
#                                              Main Entry
# ===============================================================================================================
if __name__ == "__main__":
    main()
