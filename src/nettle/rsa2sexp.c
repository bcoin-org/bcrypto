/* rsa2sexp.c

   Copyright (C) 2002 Niels Möller

   This file is part of GNU Nettle.

   GNU Nettle is free software: you can redistribute it and/or
   modify it under the terms of either:

     * the GNU Lesser General Public License as published by the Free
       Software Foundation; either version 3 of the License, or (at your
       option) any later version.

   or

     * the GNU General Public License as published by the Free
       Software Foundation; either version 2 of the License, or (at your
       option) any later version.

   or both in parallel, as here.

   GNU Nettle is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received copies of the GNU General Public License and
   the GNU Lesser General Public License along with this program.  If
   not, see http://www.gnu.org/licenses/.
*/

#if NETTLE_HAVE_CONFIG_H
# include "config.h"
#endif

#include "rsa.h"

#include "sexp.h"

int
rsa_keypair_to_sexp(struct nettle_buffer *buffer,
		    const char *algorithm_name,
		    const struct rsa_public_key *pub,
		    const struct rsa_private_key *priv)
{
  if (!algorithm_name)
    algorithm_name = "rsa-pkcs1";
  
  if (priv)
    return sexp_format(buffer,
		       "(private-key(%0s(n%b)(e%b)"
		       "(d%b)(p%b)(q%b)(a%b)(b%b)(c%b)))",
		       algorithm_name, pub->n, pub->e,
		       priv->d, priv->p, priv->q,
		       priv->a, priv->b, priv->c);
  else
    return sexp_format(buffer, "(public-key(%0s(n%b)(e%b)))",
		       algorithm_name, pub->n, pub->e);
}
