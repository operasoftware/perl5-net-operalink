#!/usr/bin/env perl

use strict;
use warnings;
use Test::More;

plan tests => 5;

use_ok('Net::OperaLink');
use_ok('Net::OperaLink::Datatype');
use_ok('Net::OperaLink::Bookmark');
use_ok('Net::OperaLink::Speeddial');

ok(1, 'Basic classes loaded');

