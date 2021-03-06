<?php

declare(strict_types = 1);

namespace Sop\PKCS5\ASN1\AlgorithmIdentifier;

use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\BlockCipherAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\DESCBCAlgorithmIdentifier;
use Sop\PKCS5\HashFunc\HashFunc;
use Sop\PKCS5\HashFunc\MD5;

/**
 * Algorithm identifier for password-based encryption scheme with MD5 and DES.
 *
 * @see https://tools.ietf.org/html/rfc2898#appendix-A.3
 */
class PBEWithMD5AndDESCBCAlgorithmIdentifier extends PBES1PKCS5AlgorithmIdentifier
{
    /**
     * Constructor.
     *
     * @param string $salt            Salt
     * @param int    $iteration_count Iteration count
     */
    public function __construct(string $salt, int $iteration_count)
    {
        parent::__construct($salt, $iteration_count);
        $this->_oid = self::OID_PBE_WITH_MD5_AND_DES_CBC;
    }

    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'pbeWithMD5AndDES-CBC';
    }

    /**
     * {@inheritdoc}
     */
    public function hashFunc(): HashFunc
    {
        return new MD5();
    }

    /**
     * {@inheritdoc}
     */
    public function blockCipher(): BlockCipherAlgorithmIdentifier
    {
        return new DESCBCAlgorithmIdentifier();
    }
}
