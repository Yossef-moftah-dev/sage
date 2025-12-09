import random

from sage.crypto.public_key.key_exchange.key_exchange_base import KeyExchangeBase
from sage.rings.integer import Integer
from sage.schemes.elliptic_curves.ell_curve_isogeny import EllipticCurveIsogeny


class SIDH(KeyExchangeBase):
    """
    Supersingular isogeny Diffie-Hellman key exchange.

    TODO: Cite Costello paper for exampe
    
    TESTS:

    sage: from sage.crypto.public_key.key_exchange.sidh import SIDH
    sage: e_A = 4
    sage: e_B = 3
    sage: p = 2^e_A * 3^e_B - 1
    sage: K.<i> = GF(p^2, modulus=x^2 + 1)
    sage: a0 = 329 * i + 423
    sage: E = EllipticCurve(K, [0, a0, 0, 1, 0])
    sage: P_A = E(100 * i + 248, 304 * i + 199)
    sage: Q_A = E(426 * i + 394, 51 * i + 79)
    sage: P_B = E(358 * i + 275, 410 * i + 104)
    sage: Q_B = E(20 * i + 185, 281 * i + 239)
    sage: toy_sidh = SIDH(p, e_A, e_B, E, P_A, P_B, Q_A, Q_B)
    sage: TestSuite(toy_sidh).run()
    """

    def __init__(self, p, e_A, e_B, E, P_A, P_B, Q_A, Q_B):
        self._p = p
        self._e_A = e_A
        self._e_B = e_B
        self._E = E
        self._P_A = P_A
        self._P_B = P_B
        self._Q_A = Q_A
        self._Q_B = Q_B
    
    def alice_secret_key(self): 
        k_A = random.randint(0, self._e_A)
        return Integer(k_A)
    
    def bob_secret_key(self):
        k_B = random.randint(0, self._e_B)
        return Integer(k_B)
    
    def alice_public_key(self, alice_secret_key):
        phi_A = self.alice_first_secret_isogeny(alice_secret_key)
        E_A = phi_A.codomain()
        P_B1 = phi_A(self._P_B)
        Q_B1 = phi_A(self._Q_B)
        return (E_A, P_B1, Q_B1)
    
    def bob_public_key(self, bob_secret_key):
        phi_B = self.bob_first_secret_isogeny(bob_secret_key)
        E_B = phi_B.codomain()
        P_A1 = phi_B(self._P_A)
        Q_A1 = phi_B(self._Q_A)
        return (E_B, P_A1, Q_A1)
    
    def alice_compute_shared_secret(self, alice_secret_key, bob_public_key):
        phi_A1 = self.alice_second_secret_isogeny(self, alice_secret_key, bob_public_key)
        E_AB = phi_A1.codomain()
        j_A = E_AB.j_invariant()
        return j_A
    
    def bob_compute_shared_secret(self, bob_secret_key, alice_public_key):
        phi_B1 = self.bob_second_secret_isogeny(self, bob_secret_key, alice_public_key)
        E_BA = phi_B1.codomain()
        j_B = E_BA.j_invariant()
        return j_B
    
    def alice_first_secret_isogeny(self, alice_secret_key):
        isogenyMap = self.buildIsogenyByBreakingDown(alice_secret_key, 2, self._E, self._P_A, self._Q_A)
        return isogenyMap[0]
    
    def bob_first_secret_isogeny(self, bob_secret_key):
        isogenyMap = self.buildIsogenyByBreakingDown(bob_secret_key, 3, self._E, self._P_B, self.Q_B)
        return isogenyMap[0]
    
    def alice_second_secret_isogeny(self, alice_secret_key, bob_public_key):
        (E_B, P_A1, Q_A1) = bob_public_key
        isogenyMap = self.buildIsogenyByBreakingDown(alice_secret_key, 2, E_B, P_A1, Q_A1)
        return isogenyMap[0]
    
    def bob_second_secret_isogeny(self, bob_secret_key, alice_public_key):
        (E_A, P_B1, Q_B1) = alice_public_key
        isogenyMap = self.buildIsogenyByBreakingDown(bob_secret_key, 3, E_A, P_B1, Q_B1)
        return isogenyMap[0]
    
    def buildIsogenyByBreakingDown(self, person_secret_key, ell, domain_EC, P_generate, Q_generate):
        sequenceOfIsogenies = []
        if ell == 2:
            e_power = self._e_A
        elif ell == 3:
            e_power = self._e_B
        temp_S = P_generate + person_secret_key * Q_generate
        temp_R = (ell^(e_power - 1)) * temp_S
        temp_phi = EllipticCurveIsogeny(domain_EC, temp_R)
        temp_S = temp_phi(temp_S)
        sequenceOfIsogenies.append((temp_phi, temp_S))
        finalIsogeny = temp_phi
        for i in range(1, e_power):
            (temp_phi_i1, temp_S_i1) = sequenceOfIsogenies(i-1)
            temp_R = (ell^(e_power - i - 1)) * temp_S_i1
            temp_phi_i = EllipticCurveIsogeny(temp_phi_i1.codomain(), temp_R)
            temp_S_i = temp_phi_i(temp_S_i1)
            sequenceOfIsogenies.append((temp_phi_i, temp_S_i))
            finalIsogeny = temp_phi_i * finalIsogeny
        return (finalIsogeny, sequenceOfIsogenies)
