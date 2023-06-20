import random
import sys
from struct import pack, unpack
from PyQt5 import QtCore
from PyQt5 import QtWidgets
from PyQt5 import QtGui


# do dodania okna interfejsu graficznego dla MD4, dodac customowe testy w oknach, dodac opcje zeby mozna bylo zaszyfrowac
# skrot wiadomosci md4
class RSA_Error(Exception):
    def __init__(self) -> None:
        pass


def test_rsa(msg=None):
    if msg is None:
        lista_napisow = []
        for x in range(1, 10):
            napis = ''.join([chr(random.randrange(65, 91)) for y in range(5, 26)])
            lista_napisow.append(napis)
        for y in lista_napisow:
            rsa = RSA.from_random_primes(128)
            deszyfr = rsa.decrypt(rsa.encrypt(y))
            if y != deszyfr:
                raise RSA_Error
        return True


class MD4_Error(Exception):
    def __init__(self):
        pass


def test_md4():
    napisy = ['message_digest', 'Ala ma kota', 'test', 'The quick brown fox jumps over the lazy dog']
    hasze = ['a4a92b2f7b0a2c96529f69ffdb86c94d',
             'e1fefa8fb989926d1322695a4ae34503',
             'db346d691d7acc4dc2625db19f9e3f52',
             '1bee69a46ba811185c194762abaeae90']

    for x in range(4):
        md4 = MD4.from_string(napisy[x])
        if hasze[x] != md4.get_hash():
            raise MD4_Error
    return True

    pass


class Okno(QtWidgets.QWidget):
    width, height = 320, 240
    listaokien = []

    def __init__(self):
        super().__init__()
        pass

    @classmethod
    def okno_main(cls) -> object:
        """'Konstruktor' zwracający główne okno aplikacji"""
        new = Okno()
        new.setWindowTitle("ENKRYPTOINATOR")
        new.setMaximumSize(Okno.width, Okno.height)
        new.setMinimumSize(Okno.width, Okno.height)
        new.font = QtGui.QFont()
        new.font.setFamily("Arial")
        # new.font.setStyle()
        new.vlayout1 = QtWidgets.QVBoxLayout()
        new.button1 = QtWidgets.QPushButton("Generuj RSA")
        new.button1.clicked.connect(lambda: new.okno_rsa())
        new.button2 = QtWidgets.QPushButton("Sprawdź")
        new.label1 = QtWidgets.QLabel("ENKRYPTOINATOR")
        new.vlayout1.addWidget(new.label1)
        new.label1.setAlignment(QtCore.Qt.AlignCenter)
        new.vlayout1.addWidget(new.button1)
        new.vlayout1.addWidget(new.button2)
        new.setLayout(new.vlayout1)
        Okno.listaokien.append(new)
        return new
        pass

    @classmethod
    def okno_rsa(cls) -> object:
        """
        'Konstruktor' zwracający okno generacji RSA. W teorii różni się bardzo dużo
        niż gdybym zrobił osobną klasę, w praktyce niedużo
        """
        new = Okno()
        new.setWindowTitle("Generuj RSA")
        new.setMaximumSize(Okno.width, Okno.height)
        new.setMinimumSize(Okno.width, Okno.height)
        new.font = QtGui.QFont()
        new.font.setFamily("Arial")
        new.label1 = QtWidgets.QLabel("Rozmiar liczby pierwszej w bitach (m. 4096)")
        new.spinbox1 = QtWidgets.QSpinBox()
        new.spinbox1.setMaximum(4096)
        new.spinbox1.setMinimum(8)
        new.vlayout1 = QtWidgets.QVBoxLayout()
        new.hlayout1 = QtWidgets.QHBoxLayout()
        new.hlayout1.addWidget(new.label1)
        new.hlayout1.addWidget(new.spinbox1)
        new.button1 = QtWidgets.QPushButton("Generuj")
        new.button1.clicked.connect(lambda: Okno.generuj_rsa(new.spinbox1.value()))
        new.vlayout1.addLayout(new.hlayout1)
        new.vlayout1.addWidget(new.button1)
        new.setLayout(new.vlayout1)
        Okno.listaokien.append(new)
        new.show()
        return new

    @staticmethod
    def generuj_rsa(length) -> None:
        rsa = RSA.from_random_primes(length)
        Okno.push_to_file(str(rsa.public_key))
        pass

    @classmethod
    def okno_md4(cls):
        """Konstruktor' zwracający okno MD4 aplikacji"""
        new = Okno()
        return new

    @staticmethod
    def push_to_file(msg: str) -> None:
        """Metoda do zapisywania klucza publicznego do pliku"""
        plik = open("publiczny.txt", "w")
        plik.write(msg)
        plik.close()
        pass


class MD4(object):
    """
    Klasa MD4 reprezentująca dane wejściowe jako ciąg bajtów.
    Atrybuty klasowe A, B, C, D to stałe wartości ze stanu początkowego konstrukcji kryptograficznej
    funkcji skrótu Merkle'a-Darmgarda. Stan początkowy określany jest jako s0 = (A, B, C, D)

    """
    A, B, C, D = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    enkoding = 'ascii'

    def __init__(self, napis):
        self.x = napis
        pass

    def __repr__(self):
        return repr(int(self.x, 16))

    @classmethod
    def from_string(cls, napis: str) -> object:
        """
        Metoda klasy MD4 wywołująca konstruktor dla danych wejściowych typu string.
        :param napis: Napis (string)
        :return: Instancja klasy MD4
        """
        return cls(bytes(napis, MD4.enkoding))
        pass

    @classmethod
    def from_file(cls, sciezka: str) -> object:
        """
        Metoda klasy MD4 wywołująca konstruktor czytający dane z pliku o podanej ścieżce.
        :param sciezka: ścieżka do pliku
        :return: Instancja klasy MD4
        """
        plik = open(sciezka, 'r')
        napis = plik.read()
        plik.close()
        return cls(bytes(napis, MD4.enkoding))
        pass

    @staticmethod
    def rotateleft(a: int, b: int) -> int:
        """
        Metoda pozwalająca obracać w lewo liczby typu int.
        :param a: int
        :param b: int
        :return: int
        """
        return ((a << b) & 0xFFFFFFFF) | (a >> (32 - b))
        pass

    @staticmethod
    def __f(x: int, y: int, z: int) -> int:
        """
        Metoda pomocnicza do implementacji algorytmu MD4
        :param x: uint32
        :param y: uint32
        :param z: uint32
        :return: uint32
        """
        return (x & y) | (~x & z)
        pass

    @staticmethod
    def __g(x: int, y: int, z: int) -> int:
        """
        Metoda pomocnicza do implementacji algorytmu MD4
        :param x: uint32
        :param y: uint32
        :param z: uint32
        :return: uint32
        """
        return (x & y) | (y & z) | (x & z)
        pass

    @staticmethod
    def __h(x: int, y: int, z: int) -> int:
        """
        Metoda pomocnicza do implementacji algorytmu MD4
        :param x: uint32
        :param y: uint32
        :param z: uint32
        :return: uint32
        """
        return x ^ y ^ z
        pass

    def _padding(self, dl):
        """
        Metoda dopełniająca napis do długości kongruentnej do 448 modulo 512.
        Dopełnienie składa się z ciągu zerowych bajtów.
        :param dl: długość napisu
        :return: bytes
        """
        return b'\x00' * (64 - (dl + 8) % 64)
        pass

    def _length(self, dlugosc):
        """
        Metoda zwracająca długość wiadomości w stałym rozmiarze 8 bajtów. Konwencja little-endian.
        :param dlugosc: długość napisu
        :return: bytes
        """
        return pack("<Q", dlugosc * 8)

    def get_hash(self):
        """
        Funkcja skrótu algorytmu MD4.
        :return: Wartość funkcji skrótu dla algorytmu MD4 w postaci dziesiętnej.
        """
        A, B, C, D = MD4.A * 1, MD4.B * 1, MD4.C * 1, MD4.D * 1
        hasz = bytearray(self.x)  # trik zeby hasz i self.x nie byly wskaznikiem do tego samego obiektu
        hasz += b"\x80"  # 'doczepienie' jednego bitu
        hasz += self._padding(len(hasz))
        hasz += self._length(len(self.x))

        lista = [hasz[i * 64:(i + 1) * 64] for i in
                 range((len(hasz) + 64 - 1) // 64)]  # podzial na bloki o rozmiarze 64 bajty (512 bitow)

        for chunk in lista:
            lista2 = unpack("<16I", chunk)  # unpack podzialu na bloki o rozmiarze 4 bajty

            y = 0
            omega = [3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19, 3, 7, 11, 19]
            z = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
            for x in range(16):
                A, B, C, D = D, MD4.rotateleft((A + self.__f(B, C, D) + lista2[z[x]] + y) % 2 ** 32,
                                               omega[x]), B, C  # wszystko modulo 2**32 bo ograniczenie algorytmu
                pass

            y = 1518500249
            omega = [3, 5, 9, 13, 3, 5, 9, 13, 3, 5, 9, 13, 3, 5, 9, 13]
            z = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
            for x in range(16):
                A, B, C, D = D, MD4.rotateleft((A + self.__g(B, C, D) + lista2[z[x]] + y) % 2 ** 32, omega[x]), B, C
                pass

            y = 1859775393
            omega = [3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15, 3, 9, 11, 15]
            z = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
            for x in range(16):
                A, B, C, D = D, MD4.rotateleft((A + self.__h(B, C, D) + lista2[z[x]] + y) % 2 ** 32, omega[x]), B, C
                pass

        e, f, g, h = (A + MD4.A) % 2 ** 32, (B + MD4.B) % 2 ** 32, (C + MD4.C) % 2 ** 32, (
                D + MD4.D) % 2 ** 32  # ostatni krok algorytmu

        return pack("<4I", e, f, g, h).hex()
        pass


class RSA(object):
    def __init__(self, p, q):
        self.e = 65537
        self.p = p
        self.q = q
        pass

    @classmethod
    def from_random_primes(cls, bitlength: int) -> object:
        """
        Konstruktor instancji klasy RSA na podstawie losowo wybranych liczb pierwszych z podanego zakresu bitlength.
        :param bitlength: długość liczb pierwszych w bitach
        :return: obiekt klasy RSA
        """
        pierwsze = RSA.generate(bitlength)
        return cls(pierwsze[0], pierwsze[1])

    @staticmethod
    def generate(bitlength: int) -> tuple:
        """
        Metoda służąca do generowania losowych liczb pierwszych z podanego zakresu bitlength.
        :param bitlength: długość liczb pierwszych w bitach
        :return: para (krotka) liczb pierwszych o długości bitlength
        """
        proba = 1
        while 1:
            pierwsza, druga = random.randrange(2 ** (bitlength - 1) + 1, 2 ** bitlength, 2), \
                random.randrange(2 ** (bitlength - 1) + 1, 2 ** bitlength, 2)
            if RSA.millerrabin(pierwsza) and RSA.millerrabin(druga):
                return pierwsza, druga
            proba += 1

    @staticmethod
    def eea(a: int, b: int) -> tuple:
        """
        Rozszerzony algorytm euklidesa
        :param a:
        :param b:
        :return: rozwiązanie pewnego równania diofantycznego
        """
        if a == 0:
            return b, 0, 1

        x, y, z = RSA.eea(b % a, a)
        i, j = z - (b // a) * y, y

        return x, i, j

    @staticmethod
    def millerrabin(n: int, dok=100) -> bool:
        """
        Probabilistyczny test wyboru liczb pierwszych. Przy jednej pętli takiego algorytmu jest 3/4 pewności, że liczba jest pierwsza.
        Za liczbę powtórzeń odpowiedzialna jest zmienna 'dok'.
        :param n: liczba pierwsza
        :param dok: liczba pętli
        :return: prawda/fałsz
        """
        if n == 2 or n == 3 or n == 5 or n == 7:
            return True

        if n <= 2 or n % 2 == 0 or n % 3 == 0 or n % 5 == 0 or n % 7 == 0:  # zeby szybko zakonczyc algorytm
            # jezeli podzielne przez te cyfry (czesto sie zdarza)
            return False

        s = 0
        d = n - 1
        while d % 2 == 0:
            d = d // 2
            s += 1

        for x in range(dok):
            a = random.randint(2, n - 2)
            b = pow(a, d, n)  # pow(a, b, c) oznacza tyle co (a**b)%c tylko duzo szybsze
            c = 0
            for l in range(s):
                c = (b * b) % n
                if c == 1 and b != 1 and b != n - 1:
                    return False
                b = c
            if c != 1:
                return False
        return True

    @staticmethod
    def naiwny(n: int) -> bool | None:
        """
        Naiwny algorytm sprawdzania liczby pierwszej
        :param n: liczba pierwsza
        :return: prawda/fałsz
        """
        if n < 2:
            return None
        for i in range(2, int(n ** (1 / 2)) + 1):
            if n % i == 0:
                return False
        return True

    @property
    def n(self) -> int:
        """Element klucza publicznego"""
        return self.p * self.q

    @property
    def phi(self) -> int:
        """Funkcja tocjent Eulera"""
        return (self.p - 1) * (self.q - 1)

    @property
    def public_key(self) -> tuple:
        """Krotka przedstawiająca klucz publiczny."""
        return self.n, self.e # krotka

    @property
    def d(self) -> int:
        """Element klucza prywatnego"""
        pom = list(RSA.eea(self.e, self.phi))
        pom[1] = pom[1] % self.phi  # uważać
        if pom[1] < 0:  # uważać
            pom[1] += self.phi  # uważać
        return pom[1]

    def encrypt(self, msg: str) -> list:
        """
        Metoda szyfrująca napis. Założenie: szyfr szyfruje pojedyncze znaki
        (rozmiar bloku równy 1 bajt (2 bajty czasem)).
        Pojedyncze znaki są reprezentowane za pomocą wartości z tabeli kodowania ASCII.
        :param msg: napis typu string
        :return: lista zaszyfrowanych znaków
        """
        return [pow(ord(char), self.e, self.n) for char in msg]
        pass

    def decrypt(self, msg: list) -> str:
        """
        Metoda deszyfrująca napis. Założenie: szyfr odbył się na pojedynczych znakach
        :param msg: lista zaszyfrowanych znaków
        :return: napis typu string
        """
        return ''.join([chr(pow(char, self.d, self.n)) for char in
                        msg])  # pow(a, b, c) oznacza tyle co (a**b)%c tylko duzo szybsze
        pass


# app = QtWidgets.QApplication(sys.argv)
# okno = Okno.okno_main()
# okno.show()
# sys.exit(app.exec_())

# print(test_rsa())
# md4 = MD4.from_string("Ala ma kota")
# print(md4.get_hash())
print(test_rsa(), test_md4())
