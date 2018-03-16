(ns caesium.crypto.sign.ed25519
  (:refer-clojure :exclude [bytes])
  (:require [caesium.binding :as b]
            [caesium.byte-bufs :as bb]))

(b/defconsts [bytes
              seedbytes
              publickeybytes
              secretkeybytes
              messagebytes-max])

(defn ed25519-pk-to-curve25519-buf!
  [curve25519_pk ed25519_pk]
  (b/call! crypto_sign_ed25519_pk_to_curve25519 curve25519_pk ed25519_pk))

(defn ed25519_pk_to_curve25519 [ed25519_pk]
  (let [curve25519_pk (bb/alloc publickeybytes)]
    (ed25519-pk-to-curve25519-buf! curve25519_pk (bb/->indirect-byte-buf ed25519_pk))
    (bb/->bytes curve25519_pk)))


(defn ed25519-sk-to-curve25519-buf!
  [curve25519_sk ed25519_sk]
  (b/call! crypto_sign_ed25519_sk_to_curve25519 curve25519_sk ed25519_sk))

(defn ed25519_sk_to_curve25519 [ed25519_sk]
  (let [curve25519_sk (bb/alloc publickeybytes)]
    (ed25519-sk-to-curve25519-buf! curve25519_sk (bb/->indirect-byte-buf ed25519_sk))
    (bb/->bytes curve25519_sk)))
