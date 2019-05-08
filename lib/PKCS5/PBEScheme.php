<?php

declare(strict_types = 1);

namespace Sop\PKCS5;

use Sop\CryptoBridge\Crypto;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBEAlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBES1AlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBES2AlgorithmIdentifier;
use Sop\PKCS5\PBEKD\PBEKDF;
use Sop\PKCS5\PRF\PRF;

/**
 * Base class for password-based encryption schemes.
 *
 * @see https://tools.ietf.org/html/rfc2898#section-6
 */
abstract class PBEScheme
{
    /**
     * Encrypt data.
     *
     * @param string $data     Plaintext
     * @param string $password Password
     *
     * @return string Ciphertext
     */
    abstract public function encrypt(string $data, string $password): string;

    /**
     * Encrypt data with pre-derived key.
     *
     * @param string $data Plaintext
     * @param string $key  Derived key
     *
     * @return string Ciphertext
     */
    abstract public function encryptWithKey(string $data, string $key): string;

    /**
     * Decrypt data.
     *
     * @param string $data     Ciphertext
     * @param string $password Password
     *
     * @return string Plaintext
     */
    abstract public function decrypt(string $data, string $password): string;

    /**
     * Decrypt data with pre-derived key.
     *
     * @param string $data Ciphertext
     * @param string $key  Derived key
     *
     * @return string Plaintext
     */
    abstract public function decryptWithKey(string $data, string $key): string;

    /**
     * Get key-derivation function.
     *
     * @return PBEKDF
     */
    abstract public function kdf(): PBEKDF;

    /**
     * Get PBEScheme by algorithm identifier.
     *
     * @param PBEAlgorithmIdentifier $algo   Algorithm identifier
     * @param null|Crypto            $crypto Crypto engine, use default if not set
     *
     * @throws \UnexpectedValueException
     *
     * @return self
     */
    public static function fromAlgorithmIdentifier(PBEAlgorithmIdentifier $algo,
        ?Crypto $crypto = null): PBEScheme
    {
        if ($algo instanceof PBES1AlgorithmIdentifier) {
            return new PBES1($algo->hashFunc(), $algo->blockCipher(),
                $algo->salt(), $algo->iterationCount(), $crypto);
        }
        if ($algo instanceof PBES2AlgorithmIdentifier) {
            $prf = PRF::fromAlgorithmIdentifier(
                $algo->kdfAlgorithmIdentifier()->prfAlgorithmIdentifier());
            return new PBES2($prf, $algo->esAlgorithmIdentifier(), $algo->salt(),
                $algo->iterationCount(), $crypto);
        }
        throw new \UnexpectedValueException(
            sprintf('No encryption scheme for %s algorithm.', $algo->name()));
    }
}
