<?php

declare(strict_types = 1);

namespace Sop\PKCS5\ASN1\AlgorithmIdentifier;

use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\BlockCipherAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\RC2CBCAlgorithmIdentifier;
use Sop\PKCS5\HashFunc\HashFunc;
use Sop\PKCS5\HashFunc\MD2;

/**
 * Algorithm identifier for password-based encryption scheme with MD2 and RC2.
 *
 * @see https://tools.ietf.org/html/rfc2898#appendix-A.3
 */
class PBEWithMD2AndRC2CBCAlgorithmIdentifier extends PBES1PKCS5AlgorithmIdentifier
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
        $this->_oid = self::OID_PBE_WITH_MD2_AND_RC2_CBC;
    }

    /**
     * @return string
     */
    public function name(): string
    {
        return 'pbeWithMD2AndRC2-CBC';
    }

    /**
     * {@inheritdoc}
     */
    public function hashFunc(): HashFunc
    {
        return new MD2();
    }

    /**
     * {@inheritdoc}
     */
    public function blockCipher(): BlockCipherAlgorithmIdentifier
    {
        return new RC2CBCAlgorithmIdentifier();
    }
}
