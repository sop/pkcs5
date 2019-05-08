<?php

declare(strict_types = 1);

namespace Sop\PKCS5;

use Sop\CryptoBridge\Crypto;
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\CipherAlgorithmIdentifier;
use Sop\PKCS5\HashFunc\HashFunc;
use Sop\PKCS5\PBEKD\PBEKDF;
use Sop\PKCS5\PBEKD\PBEKDF1;

/**
 * Implements password-based encryption scheme #1.
 *
 * @see https://tools.ietf.org/html/rfc2898#section-6.1
 */
class PBES1 extends PBEScheme
{
    /**
     * Hash functor.
     *
     * @var HashFunc
     */
    protected $_hashFunc;

    /**
     * Cipher algorithm.
     *
     * @var CipherAlgorithmIdentifier
     */
    protected $_cipher;

    /**
     * Salt.
     *
     * @var string
     */
    protected $_salt;

    /**
     * Iteration count.
     *
     * @var int
     */
    protected $_iterationCount;

    /**
     * Crypto engine.
     *
     * @var Crypto
     */
    protected $_crypto;

    /**
     * Padding instance.
     *
     * @var Padding
     */
    protected $_padding;

    /**
     * Constructor.
     *
     * @param HashFunc                  $hash_func       Hash function
     * @param CipherAlgorithmIdentifier $cipher          Cipher algorithm
     * @param string                    $salt            Salt
     * @param int                       $iteration_count Iteration count
     * @param null|Crypto               $crypto          Crypto implementation,
     *                                                   use default if not set
     */
    public function __construct(HashFunc $hash_func,
        CipherAlgorithmIdentifier $cipher, string $salt, int $iteration_count,
        ?Crypto $crypto = null)
    {
        $this->_hashFunc = $hash_func;
        $this->_cipher = $cipher;
        $this->_salt = $salt;
        $this->_iterationCount = $iteration_count;
        $this->_crypto = $crypto ?? Crypto::getDefault();
        $this->_padding = new Padding(8);
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt(string $data, string $password): string
    {
        $key = $this->kdf()->derive($password, $this->_salt,
            $this->_iterationCount, 16);
        return $this->encryptWithKey($data, $key);
    }

    /**
     * {@inheritdoc}
     *
     * @throws \UnexpectedValueException If key length is invalid
     */
    public function encryptWithKey(string $data, string $key): string
    {
        if (16 !== strlen($key)) {
            throw new \UnexpectedValueException('Invalid key length.');
        }
        $algo = $this->_cipher->withInitializationVector(substr($key, 8, 8));
        return $this->_crypto->encrypt($this->_padding->add($data),
            substr($key, 0, 8), $algo);
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt(string $data, string $password): string
    {
        $key = $this->kdf()->derive($password, $this->_salt,
            $this->_iterationCount, 16);
        return $this->decryptWithKey($data, $key);
    }

    /**
     * {@inheritdoc}
     *
     * @throws \UnexpectedValueException If decryption fails
     */
    public function decryptWithKey(string $data, string $key): string
    {
        if (16 !== strlen($key)) {
            throw new \UnexpectedValueException('Invalid key length.');
        }
        try {
            $algo = $this->_cipher->withInitializationVector(substr($key, 8, 8));
            $str = $this->_crypto->decrypt($data, substr($key, 0, 8), $algo);
            return $this->_padding->remove($str);
        } catch (\RuntimeException $e) {
            throw new \UnexpectedValueException('Decryption failed.', 0, $e);
        }
    }

    /**
     * {@inheritdoc}
     */
    public function kdf(): PBEKDF
    {
        return new PBEKDF1($this->_hashFunc);
    }
}
