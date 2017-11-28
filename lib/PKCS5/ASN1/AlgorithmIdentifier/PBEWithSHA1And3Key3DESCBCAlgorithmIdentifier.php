<?php

declare(strict_types = 1);

namespace Sop\PKCS5\ASN1\AlgorithmIdentifier;

use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\BlockCipherAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\DESEDE3CBCAlgorithmIdentifier;
use Sop\PKCS5\HashFunc\HashFunc;
use Sop\PKCS5\HashFunc\SHA1;

/**
 * Algorithm identifier for password-based encryption scheme with SHA-1 and
 * 3-key triple-DES-CBC.
 *
 * @link https://tools.ietf.org/html/rfc7292#appendix-C
 */
class PBEWithSHA1And3Key3DESCBCAlgorithmIdentifier extends PBES1PKCS12AlgorithmIdentifier
{
    /**
     * Constructor.
     *
     * @param string $salt Salt
     * @param int $iteration_count Iteration count
     */
    public function __construct(string $salt, int $iteration_count)
    {
        parent::__construct($salt, $iteration_count);
        $this->_oid = self::OID_PBE_WITH_SHA1_AND_3KEY_3DES_CBC;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function name(): string
    {
        return "pbeWithSHAAnd3-KeyTripleDES-CBC";
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function hashFunc(): HashFunc
    {
        return new SHA1();
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function blockCipher(): BlockCipherAlgorithmIdentifier
    {
        return new DESEDE3CBCAlgorithmIdentifier();
    }
}
