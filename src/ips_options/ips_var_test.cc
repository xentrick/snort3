//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2002-2013 Sourcefire, Inc.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------
// ips_var_test.cc author Nicholas Mavis <nmavis@cisco.com>


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "framework/cursor.h"
#include "framework/endianness.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "hash/hash_key_operations.h"
#include "log/messages.h"
#include "profiler/profiler.h"
#include "protocols/packet.h"
#include "utils/util.h"

#include "detection/detect_trace.h"
#include "trace/trace_api.h"

#include "extract.h"

using namespace snort;
using namespace std;

static THREAD_LOCAL ProfileStats varTestPerfStats;

#define s_name "var_test"

enum VarTestOper
{
    CHECK_EQ,
    CHECK_LT,
    CHECK_GT,
    CHECK_LTE,
    CHECK_GTE,
    CHECK_AND,
    CHECK_XOR
};

struct VarTestData : public ByteData
{
    int8_t val_var;
    VarTestOper opcode;
    bool not_flag;
    int8_t cmp_var;
};

// -----------------------------------------------------------------------------
// static functions
// -----------------------------------------------------------------------------

static inline bool var_test_check(VarTestOper op, uint32_t val, uint32_t cmp,
    bool not_flag)
{
    bool success = false;

    switch ( op )
    {
    case CHECK_EQ:
        success = (val == cmp);
        break;

    case CHECK_LT:
        success = (val < cmp);
        break;

    case CHECK_GT:
        success = (val > cmp);
        break;

    case CHECK_LTE:
        success = (val <= cmp);
        break;

    case CHECK_GTE:
        success = (val >= cmp);
        break;

    case CHECK_AND:
        success = ((val & cmp) > 0);
        break;

    case CHECK_XOR:
        success = ((val ^ cmp) > 0);
        break;
    }

    if (not_flag)
    {
        success = !success;
    }

    return success;
}

class VarTestOption : public IpsOption
{
public:
    VarTestOption(const VarTestData& c) : IpsOption(s_name), config(c) { }

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    EvalStatus eval(Cursor&, Packet*) override;

    // CursorActionType get_cursor_type() const override
    // { return CAT_READ; }

private:
    VarTestData config;
};

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

uint32_t VarTestOption::hash() const
{
    uint32_t a = config.val_var;
    uint32_t b = config.cmp_var;
    uint32_t c = config.opcode;

    mix(a,b,c);

    b += config.not_flag ? (1 << 24) : 0;

    mix(a,b,c);

    a += IpsOption::hash();

    mix(a,b,c);
    finalize(a,b,c);

    return c;
}

bool VarTestOption::operator==(const IpsOption& ips) const
{
    if (!IpsOption::operator==(ips))
        return false;

    const VarTestOption& rhs = (const VarTestOption&)ips;
    const VarTestData* left = &config;
    const VarTestData* right = &rhs.config;

    if (( left->val_var == right->val_var) and
        ( left->opcode == right->opcode) and
        ( left->not_flag == right->not_flag) and
        ( left->cmp_var == right->cmp_var))
    {
        return true;
    }

    return false;
}

IpsOption::EvalStatus VarTestOption::eval(Cursor& c, Packet* p)
{
    // cppcheck-suppress unreadVariable
    RuleProfile profile(varTestPerfStats);

    VarTestData* btd = (VarTestData*)&config;

    // Get values from byte_extract variables, if present.
    uint32_t cmp_value;
    if (btd->cmp_var >= 0 and btd->cmp_var < NUM_IPS_OPTIONS_VARS)
    {
        GetVarValueByIndex(&cmp_value, btd->cmp_var);
        debug_logf(detection_trace, TRACE_RULE_VARS, nullptr,
            "cmp_value: %d\n", cmp_value
        );
    }
    else
    {
        cmp_value = btd->cmp_var;
        debug_logf(detection_trace, TRACE_RULE_VARS, nullptr,
            "cmp_value else: %d\n", cmp_value
        );
    }


    // Get values from byte_extract variables. First opt must be variable
    uint32_t value;
    if (btd->val_var >= 0 and btd->val_var < NUM_IPS_OPTIONS_VARS)
    {
        GetVarValueByIndex(&value, btd->val_var);
        debug_logf(detection_trace, TRACE_RULE_VARS, nullptr,
            "value: %d\n", value
        );
    }
    else
        return NO_MATCH;

    if (var_test_check(btd->opcode, value, cmp_value, btd->not_flag))
        return MATCH;

    return NO_MATCH;
}

//-------------------------------------------------------------------------
// api
//-------------------------------------------------------------------------

static void parse_operator(const char* oper, VarTestData& idx)
{
    const char* cptr = oper;

    if (*cptr == '!')
    {
        idx.not_flag = true;
        cptr++;
    }

    if (idx.not_flag and strlen(cptr) == 0)
    {
        idx.opcode = CHECK_EQ;
    }
    else
    {
        /* set the opcode */
        switch (*cptr)
        {
        case '<':
            idx.opcode = CHECK_LT;
            cptr++;
            if (*cptr == '=')
                idx.opcode = CHECK_LTE;
            else
                cptr--;
            break;

        case '=':
            idx.opcode = CHECK_EQ;
            break;

        case '>':
            idx.opcode = CHECK_GT;
            cptr++;
            if (*cptr == '=')
                idx.opcode = CHECK_GTE;
            else
                cptr--;
            break;

        case '&':
            idx.opcode = CHECK_AND;
            break;

        case '^':
            idx.opcode = CHECK_XOR;
            break;

        default:
            ParseError("var_test unknown operator (%s)", oper);
            return;
        }

        cptr++;
        if (strlen(cptr))
            ParseError("var_test unknown operator (%s)", oper);
    }
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~variable", Parameter::PT_STRING, nullptr, nullptr,
      "variable to use for comparison" },

    { "~operator", Parameter::PT_STRING, nullptr, nullptr,
      "operation to perform to test the value" },

    { "~compare", Parameter::PT_STRING, nullptr, nullptr,
      "variable name or value to test the converted result against" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option to compare a variable against another variable or value"

class VarTestModule : public Module
{
public:
    VarTestModule() : Module(s_name, s_help, s_params) { }

    bool begin(const char*, int, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;
    bool set(const char*, Value&, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &varTestPerfStats; }

    Usage get_usage() const override
    { return DETECT; }

public:
    VarTestData data = {};
    string val_var;
    string cmp_var;
};

bool VarTestModule::begin(const char*, int, SnortConfig*)
{
    memset(&data, 0, sizeof(data));
    val_var.clear();
    cmp_var.clear();
    return true;
}

bool VarTestModule::end(const char*, int, SnortConfig*)
{
    if (val_var.empty())
        data.val_var = IPS_OPTIONS_NO_VAR;
    else
    {
        data.val_var = GetVarByName(val_var.c_str());

        if (data.val_var == IPS_OPTIONS_NO_VAR)
        {
            ParseError(INVALID_VAR_ERR_STR, "var_test", val_var.c_str());
            return false;
        }
    }

    if (cmp_var.empty())
        data.cmp_var = IPS_OPTIONS_NO_VAR;
    else
    {
        data.cmp_var = GetVarByName(cmp_var.c_str());

        if (data.cmp_var == IPS_OPTIONS_NO_VAR)
        {
            ParseError(INVALID_VAR_ERR_STR, "var_test", cmp_var.c_str());
            return false;
        }
    }

    return true;
}

bool VarTestModule::set(const char*, Value& v, SnortConfig*)
{
    if (v.is("~variable"))
        val_var = v.get_string();

    else if (v.is("~operator"))
        parse_operator(v.get_string(), data);

    else if (v.is("~compare"))
    {
        unsigned long n;
        if (v.strtoul(n))
            data.cmp_var = n;
        else
            cmp_var = v.get_string();
    }

    return true;
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{
    return new VarTestModule;
}

static void mod_dtor(Module* m)
{
    delete m;
}

static IpsOption* var_test_ctor(Module* p, OptTreeNode*)
{
    VarTestModule* m = (VarTestModule*)p;
    return new VarTestOption(m->data);
}

static void var_test_dtor(IpsOption* p)
{
    delete p;
}

static const IpsApi var_test_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, 0,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    var_test_ctor,
    var_test_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* ips_var_test[] =
#endif
{
    &var_test_api.base,
    nullptr
};

