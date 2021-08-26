from hashlib import sha256
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
import base64

from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key


def get_hexdigest(value: bytes) -> str:
    return sha256(value).hexdigest()


class MerkleNode:

    def __init__(self, value: str, left=None, right=None):
        self.left: MerkleNode = left
        self.right: MerkleNode = right
        self.parent: MerkleNode = None
        self.value = value
        self.digest = get_hexdigest(value.encode())

    def print(self, level=0):
        print(' ' * level * 3 + '|' + '_' * level * 3 + self.digest)
        if self.left:
            self.left.print(level + 1)
        if self.left:
            self.right.print(level + 1)


class MerkleTree:

    def __init__(self):
        self.leafs: list[MerkleNode] = []
        self.root: MerkleNode
        self.is_left: dict[str: bool] = {}

    def _create_tree(self):

        nodes: list[MerkleNode] = self.leafs[:]
        while len(nodes) > 1:

            tmp = []
            for i in range(0, len(nodes), 2):
                if i + 1 >= len(nodes):
                    tmp.append(nodes[i])
                    break

                left = nodes[i]
                right = nodes[i + 1]
                self.is_left[left.digest] = True
                self.is_left[right.digest] = False
                parent = MerkleNode(
                    value=(left.digest + right.digest),
                    left=left,
                    right=right
                )
                left.parent = parent
                right.parent = parent
                tmp.append(parent)
            nodes = tmp

        self.root = nodes[0]

    def add_leaf(self, value):
        self.leafs.append(MerkleNode(value=value))
        self._create_tree()

    def calc_root(self):
        return self.root.digest if self.root else None

    def _get_proof(self, current_node: MerkleNode) -> str:
        if current_node == self.root:
            return ''

        brother = current_node.parent.left.digest \
            if current_node.parent.left != current_node \
            else current_node.parent.right.digest

        return brother + ' ' + self._get_proof(current_node.parent)

    def get_proof(self, index: int) -> str:
        if not self.root or index >= len(self.leafs) or index < 0:
            return ''

        return self.root.digest + ' ' + self._get_proof(self.leafs[index])

    def _check_proof(self, acumm, digest_list) -> str:
        if not digest_list:
            return acumm

        concat = acumm + digest_list[0] if self.is_left[acumm] else digest_list[0] + acumm
        acumm = get_hexdigest(concat.encode())

        return self._check_proof(acumm, digest_list[1:])

    def check_proof(self, value: str, proof: str):
        digest_list = proof.split()[1:]

        return self._check_proof(get_hexdigest(value.encode()), digest_list) == self.root.digest

    @staticmethod
    def generate_keys():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        private_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                encryption_algorithm=serialization.NoEncryption()
                                                ).decode()

        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                             format=serialization.PublicFormat.SubjectPublicKeyInfo
                                             ).decode()

        return private_pem, public_pem

    def create_signature(self, sign_key: str) -> str:
        signature = load_pem_private_key(
            sign_key.encode(),
            password=None,
            backend=default_backend()
        ).sign(
            self.root.digest.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return (base64.b64encode(signature)).decode()

    @staticmethod
    def verify_signature(public_key: str, signature: str, text: str) -> bool:
        public_key = load_pem_public_key(public_key.encode(), backend=default_backend())

        try:
            public_key.verify(
                base64.decodebytes(signature.encode()), text.encode(),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            return True

        except InvalidSignature:
            return False


class SparseLeaf:

    def __init__(self, value: int = 0):
        self.parent: MerkleNode = None
        self.value = value
        self.digest = get_hexdigest(bytes([value]))


class SparseTree:

    def __init__(self):
        self.leafs: list[MerkleNode] = []
        self.root: MerkleNode
        self.is_left: dict[str: bool] = {}

    def _create_tree(self):

        nodes: list[MerkleNode] = self.leafs[:]

        while len(nodes) > 1:

            tmp = []
            for i in range(0, len(nodes), 2):
                if i + 1 >= len(nodes):
                    tmp.append(nodes[i])
                    break

                left = nodes[i]
                right = nodes[i + 1]
                self.is_left[left.value] = True
                self.is_left[right.value] = False
                parent = MerkleNode(
                    value=(left.digest + right.digest),
                    left=left,
                    right=right
                )
                left.parent = parent
                right.parent = parent
                tmp.append(parent)
            nodes = tmp

        self.root = nodes[0]


def main():
    while True:
        inp = input()
        func = inp.split()[0]


if __name__ == '__main__':
    # main()
    t = MerkleTree()
    for i in range(8):
        t.add_leaf(str(i))
    t.root.print()
    print(proof := t.get_proof(2))
    print(t.check_proof('2', proof))

