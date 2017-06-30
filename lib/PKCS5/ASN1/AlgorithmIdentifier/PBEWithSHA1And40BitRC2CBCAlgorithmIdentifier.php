<?php

namespace Sop\PKCS5\ASN1\AlgorithmIdentifier;

use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\RC2CBCAlgorithmIdentifier;
use Sop\PKCS5\HashFunc\SHA1;

/**
 * Algorithm identifier for password-based encryption scheme with SHA-1 and
 * 40-bit RC2.
 *
 * @link https://tools.ietf.org/html/rfc7292#appendix-C
 */
class PBEWithSHA1And40BitRC2CBCAlgorithmIdentifier extends PBES1PKCS12AlgorithmIdentifier
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
        $this->_oid = self::OID_PBE_WITH_SHA1_AND_RC2_40_CBC;
    }
    
    /**
     *
     * {@inheritdoc}
     *
     */
    public function name()
    {
        return "pbewithSHAAnd40BitRC2-CBC";
    }
    
    /**
     *
     * {@inheritdoc}
     *
     */
    public function hashFunc()
    {
        return new SHA1();
    }
    
    /**
     *
     * {@inheritdoc}
     *
     */
    public function blockCipher()
    {
        return new RC2CBCAlgorithmIdentifier(40);
    }
}
