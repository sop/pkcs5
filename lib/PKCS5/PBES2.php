<?php

namespace Sop\PKCS5;

use Sop\CryptoBridge\Crypto;
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\BlockCipherAlgorithmIdentifier;
use Sop\PKCS5\PBEKD\PBEKDF2;
use Sop\PKCS5\PRF\PRF;

/**
 * Implements password-based encryption scheme #2.
 *
 * @link https://tools.ietf.org/html/rfc2898#section-6.2
 */
class PBES2 extends PBEScheme
{
    /**
     * Pseudorandom functor.
     *
     * @var PRF $_prf
     */
    protected $_prf;
    
    /**
     * Cipher algorithm.
     *
     * @var BlockCipherAlgorithmIdentifier $_cipher
     */
    protected $_cipher;
    
    /**
     * Salt.
     *
     * @var string $_salt
     */
    protected $_salt;
    
    /**
     * Iteration count.
     *
     * @var int $_iterationCount
     */
    protected $_iterationCount;
    
    /**
     * Crypto engine.
     *
     * @var Crypto $_crypto
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
     * @param PRF $prf Pseudorandom functor
     * @param BlockCipherAlgorithmIdentifier $cipher Algorithm
     * @param string $salt Salt
     * @param int $iteration_count Iteration count
     * @param Crypto $crypto
     */
    public function __construct(PRF $prf, BlockCipherAlgorithmIdentifier $cipher,
        $salt, $iteration_count, Crypto $crypto)
    {
        $this->_prf = $prf;
        $this->_cipher = $cipher;
        $this->_salt = $salt;
        $this->_iterationCount = $iteration_count;
        $this->_crypto = $crypto;
        $this->_padding = new Padding($cipher->blockSize());
    }
    
    /**
     *
     * {@inheritdoc}
     *
     */
    public function encrypt($data, $password)
    {
        $key = $this->kdf()->derive($password, $this->_salt,
            $this->_iterationCount, $this->_cipher->keySize());
        return $this->encryptWithKey($data, $key);
    }
    
    /**
     *
     * {@inheritdoc}
     *
     */
    public function encryptWithKey($data, $key)
    {
        return $this->_crypto->encrypt($this->_padding->add($data), $key,
            $this->_cipher);
    }
    
    /**
     *
     * {@inheritdoc}
     *
     */
    public function decrypt($data, $password)
    {
        $key = $this->kdf()->derive($password, $this->_salt,
            $this->_iterationCount, $this->_cipher->keySize());
        return $this->decryptWithKey($data, $key);
    }
    
    /**
     *
     * {@inheritdoc}
     * @throws \UnexpectedValueException If decryption fails
     */
    public function decryptWithKey($data, $key)
    {
        try {
            $str = $this->_crypto->decrypt($data, $key, $this->_cipher);
            return $this->_padding->remove($str);
        } catch (\RuntimeException $e) {
            throw new \UnexpectedValueException("Decryption failed.", null, $e);
        }
    }
    
    /**
     *
     * {@inheritdoc}
     *
     */
    public function kdf()
    {
        return new PBEKDF2($this->_prf);
    }
}
