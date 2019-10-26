#!/usr/bin/rdmd @cmdfile
/*
 * Copyright (C) 2000-2014 Free Software Foundation, Inc.
 *
 * This file is part of LIBTASN1.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/*****************************************************/
/* File: CertificateExample.c                        */
/* Description: An example on how to use the ASN1    */
/*              parser with the Certificate.txt file */
/*****************************************************/

import core.runtime;
import core.stdc.config: c_ulong, c_long;
import core.stdc.stdio;
import core.stdc.string;
import core.stdc.stdlib;
import deimos.libtasn1;

import pkix_asn1_tab_mod;




/******************************************************/
/* Function : create_certificate                      */
/* Description: creates a certificate named           */
/*              "certificate1". Values are the same   */
/*              as in rfc2459 Appendix D.1            */
/* Parameters:                                        */
/*   unsigned char *der: contains the der encoding    */
/*   int *der_len: number of bytes of der string      */
/******************************************************/
private void  create_certificate (asn1_node cert_def, ubyte* der, int* der_len)
{
/+ +/
  int result, k, len;
  ubyte[1024] str;
  const(ubyte)* str2;
  asn1_node cert1 = null;
  asn1_node value = null;
  asn1_node param = null;
  asn1_node constr = null;
  char[ASN1_MAX_ERROR_DESCRIPTION_SIZE] errorDescription;
  int max_len;

  max_len = *der_len;

  result =
    asn1_create_element (cert_def, "PKIX1Implicit88.Certificate".ptr, &cert1);

  /* Use the next 3 lines to visit the empty certificate */
  /* printf("-----------------\n");
     asn1_visit_tree(cert1,"");
     printf("-----------------\n"); */

  /* version: v3(2) */
  result = asn1_write_value (cert1, "tbsCertificate.version".ptr, "v3".ptr, 0);

  /* serialNumber: 17 */
  result = asn1_write_value (cert1, "tbsCertificate.serialNumber".ptr, "17".ptr, 0);

  /* signature: dsa-with-sha1 */
  len = str.sizeof - 1;
  result =
    asn1_read_value (cert_def, "PKIX1Implicit88.id-dsa-with-sha1".ptr, str.ptr, &len);
  result =
    asn1_write_value (cert1, "tbsCertificate.signature.algorithm".ptr, str.ptr, 1);

  result = asn1_write_value (cert1, "tbsCertificate.signature.parameters".ptr,
			     null, 0);


  /* issuer: Country="US" Organization="gov" OrganizationUnit="nist" */
  result =
    asn1_write_value (cert1, "tbsCertificate.issuer".ptr, "rdnSequence".ptr, 12);

  result =
    asn1_write_value (cert1, "tbsCertificate.issuer.rdnSequence".ptr, "NEW".ptr, 1);
  result =
    asn1_write_value (cert1, "tbsCertificate.issuer.rdnSequence.?LAST".ptr, "NEW".ptr,
		      1);
  /* C */
  len = str.sizeof - 1;
  result =
    asn1_read_value (cert_def, "PKIX1Implicit88.id-at-countryName".ptr, str.ptr,
		     &len);
  result =
    asn1_write_value (cert1,
		      "tbsCertificate.issuer.rdnSequence.?LAST.?LAST.type".ptr,
		      str.ptr, 1);
  result =
    asn1_create_element (cert_def, "PKIX1Implicit88.X520countryName".ptr, &value);
  result = asn1_write_value (value, "".ptr, "US".ptr, 2);
  *der_len = max_len;
  result = asn1_der_coding (value, "".ptr, der, der_len, errorDescription.ptr);
  asn1_delete_structure (&value);
  result =
    asn1_write_value (cert1,
		      "tbsCertificate.issuer.rdnSequence.?LAST.?LAST.value".ptr,
		      der, *der_len);


  result =
    asn1_write_value (cert1, "tbsCertificate.issuer.rdnSequence".ptr, "NEW".ptr, 1);
  result =
    asn1_write_value (cert1, "tbsCertificate.issuer.rdnSequence.?LAST".ptr, "NEW".ptr,
		      1);
  /* O */
  len = str.sizeof - 1;
  result =
    asn1_read_value (cert_def, "PKIX1Implicit88.id-at-organizationName".ptr, str.ptr,
		     &len);
  result =
    asn1_write_value (cert1,
		      "tbsCertificate.issuer.rdnSequence.?LAST.?LAST.type".ptr,
		      str.ptr, 1);
  result =
    asn1_create_element (cert_def, "PKIX1Implicit88.X520OrganizationName".ptr,
			 &value);
  result = asn1_write_value (value, "".ptr, "printableString".ptr, 1);
  result = asn1_write_value (value, "printableString".ptr, "gov".ptr, 3);
  *der_len = max_len;
  result = asn1_der_coding (value, "".ptr, der, der_len, errorDescription.ptr);
  asn1_delete_structure (&value);
  result =
    asn1_write_value (cert1,
		      "tbsCertificate.issuer.rdnSequence.?LAST.?LAST.value".ptr,
		      der, *der_len);


  result =
    asn1_write_value (cert1, "tbsCertificate.issuer.rdnSequence".ptr, "NEW".ptr, 1);
  result =
    asn1_write_value (cert1, "tbsCertificate.issuer.rdnSequence.?LAST".ptr, "NEW".ptr,
		      1);

  /* OU */
  len = str.sizeof - 1;
  result =
    asn1_read_value (cert_def, "PKIX1Implicit88.id-at-organizationalUnitName".ptr,
		     str.ptr, &len);
  result =
    asn1_write_value (cert1,
		      "tbsCertificate.issuer.rdnSequence.?LAST.?LAST.type".ptr,
		      str.ptr, 1);
  result =
    asn1_create_element (cert_def,
			 "PKIX1Implicit88.X520OrganizationalUnitName".ptr,
			 &value);
  result = asn1_write_value (value, "".ptr, "printableString".ptr, 1);
  result = asn1_write_value (value, "printableString".ptr, "nist".ptr, 4);
  *der_len = max_len;
  result = asn1_der_coding (value, "".ptr, der, der_len, errorDescription.ptr);
  asn1_delete_structure (&value);
  result =
    asn1_write_value (cert1,
		      "tbsCertificate.issuer.rdnSequence.?LAST.?LAST.value".ptr,
		      der, *der_len);


  /* validity */
  result =
    asn1_write_value (cert1, "tbsCertificate.validity.notBefore".ptr, "utcTime".ptr,
		      1);
  result =
    asn1_write_value (cert1, "tbsCertificate.validity.notBefore.utcTime".ptr,
		      "970630000000Z".ptr, 1);

  result =
    asn1_write_value (cert1, "tbsCertificate.validity.notAfter".ptr, "utcTime".ptr,
		      1);
  result =
    asn1_write_value (cert1, "tbsCertificate.validity.notAfter.utcTime".ptr,
		      "971231000000Z".ptr, 1);



  /* subject: Country="US" Organization="gov" OrganizationUnit="nist" */
  result =
    asn1_write_value (cert1, "tbsCertificate.subject".ptr, "rdnSequence".ptr, 1);

  result =
    asn1_write_value (cert1, "tbsCertificate.subject.rdnSequence".ptr, "NEW".ptr, 1);
  result =
    asn1_write_value (cert1, "tbsCertificate.subject.rdnSequence.?LAST".ptr,
		      "NEW".ptr, 1);
  /* C */
  len = str.sizeof - 1;
  result =
    asn1_read_value (cert_def, "PKIX1Implicit88.id-at-countryName".ptr, str.ptr,
		     &len);
  result =
    asn1_write_value (cert1,
		      "tbsCertificate.subject.rdnSequence.?LAST.?LAST.type".ptr,
		      str.ptr, 1);
  result =
    asn1_create_element (cert_def, "PKIX1Implicit88.X520countryName".ptr, &value);
  result = asn1_write_value (value, "".ptr, "US".ptr, 2);
  *der_len = max_len;
  result = asn1_der_coding (value, "".ptr, der, der_len, errorDescription.ptr);
  asn1_delete_structure (&value);
  result =
    asn1_write_value (cert1,
		      "tbsCertificate.subject.rdnSequence.?LAST.?LAST.value".ptr,
		      der, *der_len);


  result =
    asn1_write_value (cert1, "tbsCertificate.subject.rdnSequence".ptr, "NEW".ptr, 4);
  result =
    asn1_write_value (cert1, "tbsCertificate.subject.rdnSequence.?LAST".ptr,
		      "NEW".ptr, 4);
  /* O */
  len = str.sizeof - 1;
  result =
    asn1_read_value (cert_def, "PKIX1Implicit88.id-at-organizationName".ptr, str.ptr,
		     &len);
  result =
    asn1_write_value (cert1,
		      "tbsCertificate.subject.rdnSequence.?LAST.?LAST.type".ptr,
		      str.ptr, 1);
  result =
    asn1_create_element (cert_def, "PKIX1Implicit88.X520OrganizationName".ptr,
			 &value);
  result = asn1_write_value (value, "".ptr, "printableString".ptr, 1);
  result = asn1_write_value (value, "printableString".ptr, "gov".ptr, 3);
  *der_len = max_len;
  result = asn1_der_coding (value, "".ptr, der, der_len, errorDescription.ptr);
  asn1_delete_structure (&value);
  result =
    asn1_write_value (cert1,
		      "tbsCertificate.subject.rdnSequence.?LAST.?LAST.value".ptr,
		      der, *der_len);


  result =
    asn1_write_value (cert1, "tbsCertificate.subject.rdnSequence".ptr, "NEW".ptr, 4);
  result =
    asn1_write_value (cert1, "tbsCertificate.subject.rdnSequence.?LAST".ptr,
		      "NEW".ptr, 4);
  /* OU */
  len = str.sizeof - 1;
  result =
    asn1_read_value (cert_def, "PKIX1Implicit88.id-at-organizationalUnitName".ptr,
		     str.ptr, &len);
  result =
    asn1_write_value (cert1,
		      "tbsCertificate.subject.rdnSequence.?LAST.?LAST.type".ptr,
		      str.ptr, 1);
  result =
    asn1_create_element (cert_def,
			 "PKIX1Implicit88.X520OrganizationalUnitName".ptr,
			 &value);
  result = asn1_write_value (value, "".ptr, "printableString".ptr, 1);
  result = asn1_write_value (value, "printableString".ptr, "nist".ptr, 4);
  *der_len = max_len;
  result = asn1_der_coding (value, "".ptr, der, der_len, errorDescription.ptr);
  asn1_delete_structure (&value);
  result =
    asn1_write_value (cert1,
		      "tbsCertificate.subject.rdnSequence.?LAST.?LAST.value".ptr,
		      der, *der_len);


  /* subjectPublicKeyInfo: dsa with parameters=Dss-Parms */
  len = str.sizeof - 1;
  result = asn1_read_value (cert_def, "PKIX1Implicit88.id-dsa".ptr, str.ptr, &len);
  result =
    asn1_write_value (cert1,
		      "tbsCertificate.subjectPublicKeyInfo.algorithm.algorithm".ptr,
		      str.ptr, 1);
  result =
    asn1_create_element (cert_def, "PKIX1Implicit88.Dss-Parms".ptr, &param);
  str2 = cast(const(ubyte)*) "\xd4\x38".ptr;	/* only an example */
  result = asn1_write_value (param, "p".ptr, str2, 128);
  str2 = cast(const(ubyte)*) "\xd4\x38".ptr;	/* only an example */
  result = asn1_write_value (param, "q".ptr, str2, 20);
  str2 = cast(const(ubyte)*) "\xd4\x38".ptr;	/* only an example */
  result = asn1_write_value (param, "g".ptr, str2, 128);
  *der_len = max_len;
  result = asn1_der_coding (param, "".ptr, der, der_len, errorDescription.ptr);
  asn1_delete_structure (&param);
  result =
    asn1_write_value (cert1,
		      "tbsCertificate.subjectPublicKeyInfo.algorithm.parameters".ptr,
		      der, *der_len);


  /* subjectPublicKey */
  str2 = cast(const(ubyte)*) "\x02\x81".ptr;	/* only an example */
  result =
    asn1_write_value (cert1,
		      "tbsCertificate.subjectPublicKeyInfo.subjectPublicKey".ptr,
		      str2, 1048);

  result = asn1_write_value (cert1, "tbsCertificate.issuerUniqueID".ptr, null, 0);	/* NO OPTION */
  result = asn1_write_value (cert1, "tbsCertificate.subjectUniqueID".ptr, null, 0);	/* NO OPTION */

  /* extensions */
  result = asn1_write_value (cert1, "tbsCertificate.extensions".ptr, "NEW".ptr, 1);
  len = str.sizeof - 1;
  result =
    asn1_read_value (cert_def, "PKIX1Implicit88.id-ce-basicConstraints".ptr, str.ptr,
		     &len);
  result = asn1_write_value (cert1, "tbsCertificate.extensions.?LAST.extnID".ptr, str.ptr, 1);	/*   basicConstraints */
  result =
    asn1_write_value (cert1, "tbsCertificate.extensions.?LAST.critical".ptr,
		      "TRUE".ptr, 1);
  result =
    asn1_create_element (cert_def, "PKIX1Implicit88.BasicConstraints".ptr,
			 &constr);
  result = asn1_write_value (constr, "cA".ptr, "TRUE".ptr, 1);
  result = asn1_write_value (constr, "pathLenConstraint".ptr, null, 0);
  *der_len = max_len;
  result = asn1_der_coding (constr, "".ptr, der, der_len, errorDescription.ptr);
  result = asn1_delete_structure (&constr);
  result =
    asn1_write_value (cert1, "tbsCertificate.extensions.?LAST.extnValue".ptr, der,
		      *der_len);


  result = asn1_write_value (cert1, "tbsCertificate.extensions".ptr, "NEW".ptr, 1);
  len = str.sizeof - 1;
  result =
    asn1_read_value (cert_def, "PKIX1Implicit88.id-ce-subjectKeyIdentifier".ptr,
		     str.ptr, &len);
  result = asn1_write_value (cert1, "tbsCertificate.extensions.?LAST.extnID".ptr, str.ptr, 1);	/* subjectKeyIdentifier */
  result =
    asn1_write_value (cert1, "tbsCertificate.extensions.?LAST.critical".ptr,
		      "FALSE".ptr, 1);
  str2 = cast(const(ubyte)*) "\x04\x14\xe7\x26\xc5".ptr;	/* only an example */
  result =
    asn1_write_value (cert1, "tbsCertificate.extensions.?LAST.extnValue".ptr,
		      str2, 22);


  /* signatureAlgorithm: dsa-with-sha  */
  len = str.sizeof - 1;
  result =
    asn1_read_value (cert_def, "PKIX1Implicit88.id-dsa-with-sha1".ptr, str.ptr, &len);
  result = asn1_write_value (cert1, "signatureAlgorithm.algorithm".ptr, str.ptr, 1);
  result = asn1_write_value (cert1, "signatureAlgorithm.parameters".ptr, null, 0);	/* NO OPTION */


  /* signature */
  *der_len = max_len;
  result =
    asn1_der_coding (cert1, "tbsCertificate".ptr, der, der_len, errorDescription.ptr);
  if (result != ASN1_SUCCESS)
    {
      printf ("\n'tbsCertificate' encoding creation: ERROR\n");
    }
  /* add the lines for the signature on der[0]..der[der_len-1]: result in str2 */
  result = asn1_write_value (cert1, "signature".ptr, str2, 368);	/* dsa-with-sha */


  /* Use the next 3 lines to visit the certificate */
  /* printf("-----------------\n");
     asn1_visit_tree(cert1,"");
     printf("-----------------\n"); */

  *der_len = max_len;
  result = asn1_der_coding (cert1, "".ptr, der, der_len, errorDescription.ptr);
  if (result != ASN1_SUCCESS)
    {
      printf ("\n'certificate' encoding creation: ERROR\n");
      return;
    }

  /* Print the 'Certificate1' DER encoding */
  printf ("-----------------\nCertificate Encoding:\nNumber of bytes=%i\n",
	  *der_len);
  for (k = 0; k < *der_len; k++)
    printf ("%02x ", der[k]);
  printf ("\n-----------------\n");

  /* Clear the "certificate1" structure */
  asn1_delete_structure (&cert1);
/+ +/
}



/******************************************************/
/* Function : get_certificate                         */
/* Description: creates a certificate named           */
/*              "certificate2" from a der encoding    */
/*              string                                */
/* Parameters:                                        */
/*   unsigned char *der: the encoding string          */
/*   int der_len: number of bytes of der string      */
/******************************************************/
private void  get_certificate (asn1_node cert_def, ubyte* der, int der_len)
{
/******************************************************/
/* Function : get_name_type                           */
/* Description: analyze a structure of type Name      */
/* Parameters:                                        */
/*   char *root: the structure identifier             */
/*   char *answer: the string with elements like:     */
/*                 "C=US O=gov"                       */
/******************************************************/
void  get_Name_type (asn1_node cert_def, asn1_node cert, const(char)* root,
	                         ubyte* ans)
{

char*  my_ltostr (c_long v, char* str)
{
  c_long d, r;
  char[20] temp;
  int count, k, start;

  if (v < 0)
    {
      str[0] = '-';
      start = 1;
      v = -v;
    }
  else
    start = 0;

  count = 0;
  do
    {
      d = v / 10;
      r = v - d * 10;
      temp[start + count] = cast(char)('0' + r);
      count++;
      v = d;
    }
  while (v);

  for (k = 0; k < count; k++)
    str[k + start] = temp[start + count - k - 1];
  str[count + start] = 0;
  return str;
}

/+ +/
  int k, k2, result, len;
  char[ 128]  name;
  char[1024]  str;
  char[1024]  str2;
  char[ 128]  name2;
  char[   5]  counter;
  char[ 128]  name3;
  asn1_node value = null;
  char[ASN1_MAX_ERROR_DESCRIPTION_SIZE] errorDescription;
  char* answer = cast(char*) ans;
  answer[0] = 0;
  k = 1;
  do
    {
      strcpy (name.ptr, root);
      strcat (name.ptr, ".rdnSequence.?".ptr);
      my_ltostr (k, counter.ptr);
      strcat (name.ptr, counter.ptr);
      len =  str.sizeof - 1;
      result = asn1_read_value (cert, name.ptr, str.ptr, &len);
      if (result == ASN1_ELEMENT_NOT_FOUND)
	break;
      k2 = 1;
      do
	{
	  strcpy (name2.ptr, name.ptr);
	  strcat (name2.ptr, ".?".ptr);
	  my_ltostr (k2, counter.ptr);
	  strcat (name2.ptr, counter.ptr);
	  len = str.sizeof - 1;
	  result = asn1_read_value (cert, name2.ptr, str.ptr, &len);
	  if (result == ASN1_ELEMENT_NOT_FOUND)
	    break;
	  strcpy (name3.ptr, name2.ptr);
	  strcat (name3.ptr, ".type".ptr);
	  len = str.sizeof - 1;
	  result = asn1_read_value (cert, name3.ptr, str.ptr, &len);
	  strcpy (name3.ptr, name2.ptr);
	  strcat (name3.ptr, ".value".ptr);
	  if (result == ASN1_SUCCESS)
	    {
	      len = str2.sizeof - 1;
	      result =
		asn1_read_value (cert_def,
				 "PKIX1Implicit88.id-at-countryName".ptr, str2.ptr,
				 &len);
	      if (!strcmp (str.ptr, str2.ptr))
		{
		  asn1_create_element (cert_def,
				       "PKIX1Implicit88.X520OrganizationName".ptr,
				       &value);
		  len =  str.sizeof - 1;
		  asn1_read_value (cert, name3.ptr, str.ptr, &len);
		  asn1_der_decoding (&value, str.ptr, len, errorDescription.ptr);
		  len = str.sizeof - 1;
		  asn1_read_value (value, "".ptr, str.ptr, &len);	/* CHOICE */
		  strcpy (name3.ptr, str.ptr);
		  len = str.sizeof - 1;
		  asn1_read_value (value, name3.ptr, str.ptr, &len);
		  str[len] = 0;
		  strcat (answer, " C=".ptr);
		  strcat (answer, str.ptr);
		  asn1_delete_structure (&value);
		}
	      else
		{
		  len = str2.sizeof - 1;
		  result =
		    asn1_read_value (cert_def,
				     "PKIX1Implicit88.id-at-organizationName".ptr,
				     str2.ptr, &len);
		  if (!strcmp (str.ptr, str2.ptr))
		    {
		      asn1_create_element (cert_def,
					   "PKIX1Implicit88.X520OrganizationName".ptr,
					   &value);
		      len = str.sizeof - 1;
		      asn1_read_value (cert, name3.ptr, str.ptr, &len);
		      asn1_der_decoding (&value, str.ptr, len, errorDescription.ptr);
		      len = str.sizeof - 1;
		      asn1_read_value (value, "".ptr, str.ptr, &len);	/* CHOICE */
		      strcpy (name3.ptr, str.ptr);
		      len = str.sizeof - 1;
		      asn1_read_value (value, name3.ptr, str.ptr, &len);
		      str[len] = 0;
		      strcat (answer, " O=".ptr);
		      strcat (answer, str.ptr);
		      asn1_delete_structure (&value);
		    }
		  else
		    {
		      len = str2.sizeof - 1;
		      result =
			asn1_read_value (cert_def,
					 "PKIX1Implicit88.id-at-organizationalUnitName".ptr,
					 str2.ptr, &len);
		      if (!strcmp (str.ptr, str2.ptr))
			{
			  asn1_create_element (cert_def,
					       "PKIX1Implicit88.X520OrganizationalUnitName".ptr,
					       &value);
			  len = str.sizeof - 1;
			  asn1_read_value (cert, name3.ptr, str.ptr, &len);
			  asn1_der_decoding (&value, str.ptr, len,
					     errorDescription.ptr);
			  len = str.sizeof - 1;
			  asn1_read_value (value, "".ptr, str.ptr, &len);	/* CHOICE */
			  strcpy (name3.ptr, str.ptr);
			  len = str.sizeof - 1;
			  asn1_read_value (value, name3.ptr, str.ptr, &len);
			  str[len] = 0;
			  strcat (answer, " OU=".ptr);
			  strcat (answer, str.ptr);
			  asn1_delete_structure (&value);
			}
		    }
		}
	    }
	  k2++;
	}
      while (1);
      k++;
    }
  while (1);
/+ +/
}

/+ +/
  int result, len, start, end;
  ubyte[1024] str, str2;
  asn1_node cert2 = null;
  char[ASN1_MAX_ERROR_DESCRIPTION_SIZE] errorDescription;

  asn1_create_element (cert_def, "PKIX1Implicit88.Certificate".ptr, &cert2);

  result = asn1_der_decoding (&cert2, der, der_len, errorDescription.ptr);

  if (result != ASN1_SUCCESS)
    {
      printf ("Problems with DER encoding\n");
      return;
    }


  /* issuer */
  get_Name_type (cert_def, cert2, "tbsCertificate.issuer".ptr, str.ptr);
  printf ("certificate:\nissuer :%s\n", str.ptr);
  /* subject */
  get_Name_type (cert_def, cert2, "tbsCertificate.subject".ptr, str.ptr);
  printf ("subject:%s\n", str.ptr);


  /* Verify sign */
  len = str.sizeof - 1;
  result = asn1_read_value (cert2, "signatureAlgorithm.algorithm".ptr, str.ptr, &len);

  len = str2.sizeof - 1;
  result =
    asn1_read_value (cert_def, "PKIX1Implicit88.id-dsa-with-sha1".ptr, str2.ptr,
		     &len);
  if (!strcmp (cast(char*) str.ptr, cast(char*) str2.ptr))
    {				/* dsa-with-sha */

      result = asn1_der_decoding_startEnd (cert2, der, der_len,
					   "tbsCertificate".ptr, &start, &end);

      /* add the lines to calculate the sha on der[start]..der[end] */

      len = str.sizeof - 1;
      result = asn1_read_value (cert2, "signature".ptr, str.ptr, &len);

      /* compare the previous value to signature ( with issuer public key) */
    }

  /* Use the next 3 lines to visit the certificate */
  /*   printf("-----------------\n");
     asn1_visit_tree(cert2,"");
     printf("-----------------\n"); */


  /* Clear the "certificate2" structure */
  asn1_delete_structure (&cert2);
/+ +/
}

//extern const(asn1_static_node)[]  pkix_asn1_tab;

/********************************************************/
/* Function : main                                      */
/* Description: reads the certificate description.      */
/*              Creates a certificate and calculate     */
/*              the der encoding. After that creates    */
/*              another certificate from der string     */
/********************************************************/
int main ()
{
    int result, der_len;
    ubyte[1024] der;
    asn1_node PKIX1Implicit88 = null;
    char[ASN1_MAX_ERROR_DESCRIPTION_SIZE] errorDescription;

    if (1)
        result = asn1_array2tree (pkix_asn1_tab.ptr, &PKIX1Implicit88, errorDescription.ptr);
    else
        result = asn1_parser2tree ("pkix.asn", &PKIX1Implicit88, errorDescription.ptr);

    if (result != ASN1_SUCCESS)
    {
        asn1_perror (result);
        printf ("%s", errorDescription.ptr);
        exit (EXIT_FAILURE);
    }


  /* Use the following 3 lines to visit the PKIX1Implicit structures */
  /* printf("-----------------\n");
     asn1_visit_tree(PKIX1Implicit88,"PKIX1Implicit88");
     printf("-----------------\n"); */

    der_len = 1024;
    create_certificate (PKIX1Implicit88, der.ptr, &der_len);

    get_certificate (PKIX1Implicit88, der.ptr, der_len);

    /* Clear the "PKIX1Implicit88" structures */
    asn1_delete_structure (&PKIX1Implicit88);

    return EXIT_SUCCESS;
}
