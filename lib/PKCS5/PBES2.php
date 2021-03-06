<?php

declare(strict_types = 1);

namespace Sop\PKCS5;

use Sop\CryptoBridge\Crypto;
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\BlockCipherAlgorithmIdentifier;
use Sop\PKCS5\PBEKD\PBEKDF;
use Sop\PKCS5\PBEKD\PBEKDF2;
use Sop\PKCS5\PRF\PRF;

/**
 * Implements password-based encryption scheme #2.
 *
 * @see https://tools.ietf.org/html/rfc2898#section-6.2
 */
class PBES2 extends PBEScheme
{
    /**
     * Pseudorandom functor.
     *
     * @var PRF
     */
    protected $_prf;

    /**
     * Cipher algorithm.
     *
     * @var BlockCipherAlgorithmIdentifier
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
     * @param PRF                            $prf             Pseudorandom functor
     * @param BlockCipherAlgorithmIdentifier $cipher          Algorithm
     * @param string                         $salt            Salt
     * @param int                            $iteration_count Iteration count
     * @param null|Crypto                    $crypto          Crypto implementation,
     *                                                        use default if not set
     */
    public function __construct(PRF $prf, BlockCipherAlgorithmIdentifier $cipher,
        string $salt, int $iteration_count, ?Crypto $crypto = null)
    {
        $this->_prf = $prf;
        $this->_cipher = $cipher;
        $this->_salt = $salt;
        $this->_iterationCount = $iteration_count;
        $this->_crypto = $crypto ?? Crypto::getDefault();
        $this->_padding = new Padding($cipher->blockSize());
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt(string $data, string $password): string
    {
        $key = $this->kdf()->derive($password, $this->_salt,
            $this->_iterationCount, $this->_cipher->keySize());
        return $this->encryptWithKey($data, $key);
    }

    /**
     * {@inheritdoc}
     */
    public function encryptWithKey(string $data, string $key): string
    {
        return $this->_crypto->encrypt($this->_padding->add($data), $key,
            $this->_cipher);
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt(string $data, string $password): string
    {
        $key = $this->kdf()->derive($password, $this->_salt,
            $this->_iterationCount, $this->_cipher->keySize());
        return $this->decryptWithKey($data, $key);
    }

    /**
     * {@inheritdoc}
     *
     * @throws \UnexpectedValueException If decryption fails
     */
    public function decryptWithKey(string $data, string $key): string
    {
        try {
            $str = $this->_crypto->decrypt($data, $key, $this->_cipher);
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
        return new PBEKDF2($this->_prf);
    }
}
