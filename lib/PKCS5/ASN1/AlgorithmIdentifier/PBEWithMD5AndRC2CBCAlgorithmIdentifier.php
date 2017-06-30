<?php

namespace Sop\PKCS5\ASN1\AlgorithmIdentifier;

use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\RC2CBCAlgorithmIdentifier;
use Sop\PKCS5\HashFunc\MD5;

/**
 * Algorithm identifier for password-based encryption scheme with MD5 and RC2.
 *
 * @link https://tools.ietf.org/html/rfc2898#appendix-A.3
 */
class PBEWithMD5AndRC2CBCAlgorithmIdentifier extends PBES1PKCS5AlgorithmIdentifier
{
    /**
     * Constructor.
     *
     * @param string $salt Salt
     * @param int $iteration_count Iteration count
     */
    public function __construct($salt, $iteration_count)
    {
        parent::__construct($salt, $iteration_count);
        $this->_oid = self::OID_PBE_WITH_MD5_AND_RC2_CBC;
    }
    
    /**
     *
     * {@inheritdoc}
     *
     */
    public function name()
    {
        return "pbeWithMD5AndRC2-CBC";
    }
    
    /**
     *
     * {@inheritdoc}
     *
     */
    public function hashFunc()
    {
        return new MD5();
    }
    
    /**
     *
     * {@inheritdoc}
     *
     */
    public function blockCipher()
    {
        return new RC2CBCAlgorithmIdentifier();
    }
}
