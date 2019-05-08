<?php

declare(strict_types = 1);

namespace Sop\PKCS5\ASN1\AlgorithmIdentifier;

use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\BlockCipherAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\RC2CBCAlgorithmIdentifier;
use Sop\PKCS5\HashFunc\HashFunc;
use Sop\PKCS5\HashFunc\SHA1;

/**
 * Algorithm identifier for password-based encryption scheme with SHA-1 and RC2.
 *
 * @see https://tools.ietf.org/html/rfc2898#appendix-A.3
 */
class PBEWithSHA1AndRC2CBCAlgorithmIdentifier extends PBES1PKCS5AlgorithmIdentifier
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
        $this->_oid = self::OID_PBE_WITH_SHA1_AND_RC2_CBC;
    }

    /**
     * {@inheritdoc}
     */
    public function name(): string
    {
        return 'pbeWithSHA1AndRC2-CBC';
    }

    /**
     * {@inheritdoc}
     */
    public function hashFunc(): HashFunc
    {
        return new SHA1();
    }

    /**
     * {@inheritdoc}
     */
    public function blockCipher(): BlockCipherAlgorithmIdentifier
    {
        return new RC2CBCAlgorithmIdentifier();
    }
}
