<?php

declare(strict_types = 1);

namespace Sop\PKCS5\PBEKD;

use Sop\PKCS5\HashFunc\HashFunc;

/**
 * Implements key derivation function #1 used in password-based cryptography.
 *
 * @see https://tools.ietf.org/html/rfc2898#section-5.1
 */
class PBEKDF1 extends PBEKDF
{
    /**
     * Hash functor.
     *
     * @var HashFunc
     */
    protected $_hashFunc;

    /**
     * Constructor.
     *
     * @param HashFunc $hashfunc
     */
    public function __construct(HashFunc $hashfunc)
    {
        $this->_hashFunc = $hashfunc;
    }

    /**
     * {@inheritdoc}
     */
    public function derive(string $password, string $salt, int $count,
        int $length): string
    {
        if ($length > $this->_hashFunc->length()) {
            throw new \LogicException('Derived key too long.');
        }
        $key = $password . $salt;
        for ($i = 0; $i < $count; ++$i) {
            $key = $this->_hashFunc->__invoke($key);
        }
        return substr($key, 0, $length);
    }
}
