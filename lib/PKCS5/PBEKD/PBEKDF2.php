<?php

declare(strict_types = 1);

namespace Sop\PKCS5\PBEKD;

use Sop\PKCS5\PRF\PRF;

/**
 * Implements key derivation function #2 used in password-based cryptography.
 *
 * @link https://tools.ietf.org/html/rfc2898#section-5.2
 */
class PBEKDF2 extends PBEKDF
{
    /**
     * Pseudorandom functor.
     *
     * @var PRF $_prf
     */
    protected $_prf;
    
    /**
     * Constructor.
     *
     * @param PRF $prf
     */
    public function __construct(PRF $prf)
    {
        $this->_prf = $prf;
    }
    
    /**
     *
     * {@inheritdoc}
     */
    public function derive(string $password, string $salt, int $count,
        int $length): string
    {
        $hlen = $this->_prf->length();
        $l = intval(ceil($length / $hlen));
        $r = $length - ($l - 1) * $hlen;
        $blocks = array();
        for ($i = 1; $i <= $l; ++$i) {
            $blocks[] = $this->_f($password, $salt, $count, $i);
        }
        // truncate last block
        $blocks[] = substr(array_pop($blocks), 0, $r);
        $dk = implode("", $blocks);
        return substr($dk, 0, $length);
    }
    
    /**
     * XOR-sum function F.
     *
     * @param string $P
     * @param string $S
     * @param int $c
     * @param int $i
     * @return string
     */
    protected function _f(string $P, string $S, int $c, int $i): string
    {
        // compute U_1
        $U = $this->_prf->compute($P, $S . pack("N", $i));
        $result = $U;
        for ($x = 2; $x <= $c; ++$x) {
            // U_x receives feedback from U_{x-1}
            $U_x = $this->_prf->compute($P, $U);
            // add to XOR-sum
            $result ^= $U_x;
            $U = $U_x;
        }
        return $result;
    }
}
