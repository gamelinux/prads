#use inc::Module::Install;
# 
#name q(SNMP-Effective);
#all_from q(lib/SNMP/Effective.pm);
# 
#requires q(POSIX) => 0;
#requires q(SNMP) => 0;
#requires q(Tie::Array) => 0;
#requires q(Time::HiRes) => 0;
#test_requires q(Test::More) => 0;
#recommends q(Log::Log4perl) => 0;
#no_index q(examples) => 0;
# 
#WriteAll;
