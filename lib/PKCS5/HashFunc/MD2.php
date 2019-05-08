<?php

declare(strict_types = 1);

namespace Sop\PKCS5\HashFunc;

/**
 * MD2 hash function.
 */
class MD2 extends HashFunc
{
    /**
     * Constructor.
     */
    public function __construct()
    {
        $this->_length = 16;
    }

    /**
     * {@inheritdoc}
     */
    public function hash(string $data): string
    {
        return hash('md2', $data, true);
    }
}
