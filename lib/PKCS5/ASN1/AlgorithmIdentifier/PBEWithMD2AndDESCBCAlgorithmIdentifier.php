<?php

namespace Sop\PKCS5\ASN1\AlgorithmIdentifier;

use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\DESCBCAlgorithmIdentifier;
use Sop\PKCS5\HashFunc\MD2;

/**
 * Algorithm identifier for password-based encryption scheme with MD2 and DES.
 *
 * @link https://tools.ietf.org/html/rfc2898#appendix-A.3
 */
class PBEWithMD2AndDESCBCAlgorithmIdentifier extends PBES1PKCS5AlgorithmIdentifier
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
        $this->_oid = self::OID_PBE_WITH_MD2_AND_DES_CBC;
    }
    
    /**
     *
     * {@inheritdoc}
     *
     */
    public function name()
    {
        return "pbeWithMD2AndDES-CBC";
    }
    
    /**
     *
     * {@inheritdoc}
     *
     */
    public function hashFunc()
    {
        return new MD2();
    }
    
    /**
     *
     * {@inheritdoc}
     *
     */
    public function blockCipher()
    {
        return new DESCBCAlgorithmIdentifier();
    }
}
