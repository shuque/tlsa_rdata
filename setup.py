from distutils.core import setup

setup(name='tlsa_rdata',
      version='0.1',
      scripts=['tlsa_rdata'],
      description='Generate DNS TLSA record rdata',
      author='Shumon Huque',
      author_email='shuque@upenn.edu',
      url='http://github.com/shuque/tls_rdata',

      long_description = \
      """tlsa_rdata is a python program to generate DNS TLSA record rdata.""",
      )
