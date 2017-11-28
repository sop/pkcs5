<?php

declare(strict_types = 1);

namespace Sop\PKCS5;

/**
 * Implements PKCS#5 padding.
 *
 * @link https://tools.ietf.org/html/rfc8018#section-6.1.1
 */
class Padding
{
    /**
     * Padding blocksize.
     *
     * @var int
     */
    protected $_blocksize;
    
    /**
     * Constructor.
     *
     * @param int $blocksize Blocksize
     */
    public function __construct(int $blocksize = 8)
    {
        $this->_blocksize = $blocksize;
    }
    
    /**
     * Add padding.
     *
     * @param string $data
     * @return string Data padded to blocksize
     */
    public function add(string $data): string
    {
        $n = $this->_blocksize - strlen($data) % $this->_blocksize;
        return $data . str_repeat(chr($n), $n);
    }
    
    /**
     * Remove padding.
     *
     * @param string $data
     * @throws \UnexpectedValueException
     * @return string
     */
    public function remove(string $data): string
    {
        $len = strlen($data);
        if (!$len) {
            throw new \UnexpectedValueException("No padding.");
        }
        $n = ord($data[$len - 1]);
        if ($len < $n || $n > $this->_blocksize) {
            throw new \UnexpectedValueException("Invalid padding length.");
        }
        $ps = substr($data, -$n);
        if ($ps !== str_repeat(chr($n), $n)) {
            throw new \UnexpectedValueException("Invalid padding string.");
        }
        return substr($data, 0, -$n);
    }
}
