from sage.crypto.public_key.key_exchange import KeyExchange
class SIDH(keyExchange):
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
        k_A = randint(0, self._e_A)
        return k_A
    
    def bob_secret_key(self):
        k_B = randint(0, self._e_B)
        return k_B
    
    def alice_public_key(self, alice_secret_key):
        S_A = self._P_A + alice_secret_key * self._Q_A
        phi_A = EllipticCurveIsogeny(self._E, S_A)
        E_A = phi_A.codomain()
        P_B1 = phi_A(self._P_B)
        Q_B1 = phi_A(self._Q_B)
        return (E_A, P_B1, Q_B1)
    
    def bob_public_key(self, bob_secret_key):
        S_B = self._P_B + bob_secret_key * self._Q_B
        phi_B = EllipticCurveIsogeny(self._E, S_B)
        E_B = phi_B.codomain()
        P_A1 = phi_B(self._P_A)
        Q_A1 = phi_B(self._Q_A)
        return (E_B, P_A1, Q_A1)
    
    def alice_compute_shared_secret(self, alice_secret_key, bob_public_key):
        (E_B, P_A1, Q_A1) = bob_public_key
        S_A1 = P_A1 + alice_secret_key * Q_A1
        phi_A1 = EllipticCurveIsogeny(E_B, S_A1)
        E_AB = phi_A1.codomain()
        j_A = E_AB.j_invariant()
        return j_A
    
    def bob_compute_shared_secret(self, bob_secret_key, alice_public_key):
        (E_A, P_B1, Q_B1) = alice_public_key
        S_B1 = P_B1 + bob_secret_key * Q_B1
        phi_B1 = EllipticCurveIsogeny(E_A, S_B1)
        E_BA = phi_B1.codomain()
        j_B = E_BA.j_invariant()
        return j_B
    
    def runSIDH(self):
        alice_secret_key = self.alice_secret_key()
        bob_secret_key = self.bob_secret_key()
        alice_public_key = self.alice_public_key(alice_secret_key)
        bob_public_key = self.bob_public_key(bob_secret_key)
        j_A = self.alice_compute_shared_secret(alice_secret_key, bob_public_key)
        j_B = self.bob_compute_shared_secret(bob_secret_key, alice_public_key)
        if j_A == j_B:
            return "Completed"
        else:
            return "Error Occured"
    
    def alice_first_secret_isogeny(self, alice_secret_key):
        S_A = self._P_A + alice_secret_key * self._Q_A
        phi_A = EllipticCurveIsogeny(self._E, S_A)
        return phi_A
    
    def bob_first_secret_isogeny(self, bob_secret_key):
        S_B = self._P_B + bob_secret_key * self._Q_B
        phi_B = EllipticCurveIsogeny(self._E, S_B)
        return phi_B
    
    def alice_second_secret_isogeny(self, alice_secret_key, bob_public_key):
        (E_B, P_A1, Q_A1) = bob_public_key
        S_A1 = P_A1 + alice_secret_key * Q_A1
        phi_A1 = EllipticCurveIsogeny(E_B, S_A1)
        return phi_A1
    
    def bob_second_secret_isogeny(self, bob_secret_key, alice_public_key):
        (E_A, P_B1, Q_B1) = alice_public_key
        S_B1 = P_B1 + bob_secret_key * Q_B1
        phi_B1 = EllipticCurveIsogeny(E_A, S_B1)
        return phi_B1


