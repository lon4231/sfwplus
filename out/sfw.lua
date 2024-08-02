FILE = ""

function RunCode(code)
  local s_, e_ = pcall(function()
    function Tokenize(value)
      if value == nil then
        return "null"
      end
      return tostring(value)
    end

    local keywords = { "set", "global", "to", "change", "by", "define", "return", "class", "if", "then", "else", "repeat",
      "until", "skip", "stop", "while", "for", "each", "in", "end", "require" }
    local binary_operators = { "+", "-", "*", "/", "or", "and", "xor", "mod" }
    local unary_operators = { "not" }

    local functions = {
      ["debug"] = {
        ["log"] = { ["arguments"] = { "target" } },
        ["warn"] = { ["arguments"] = { "target" } },
        ["error"] = { ["arguments"] = { "target" } },
        ["write"] = { ["arguments"] = { "target" } }
      },
      ["math"] = {
        ["random"] = { ["arguments"] = { "min", "max" } },
        ["clamp"] = { ["arguments"] = { "target", "min", "max" } },
        ["min"] = { ["arguments"] = { "target", "min" } },
        ["max"] = { ["arguments"] = { "target", "max" } },
        ["exp"] = { ["arguments"] = { "base", "exp" } },
        ["abs"] = { ["arguments"] = { "target" } },
        ["floor"] = { ["arguments"] = { "target" } },
        ["ceiling"] = { ["arguments"] = { "target" } },
        ["round"] = { ["arguments"] = { "target", "deci" } },
        ["sqrt"] = { ["arguments"] = { "target" } },
        ["sin"] = { ["arguments"] = { "target" } },
        ["cos"] = { ["arguments"] = { "target" } },
        ["tan"] = { ["arguments"] = { "target" } },
        ["asin"] = { ["arguments"] = { "target" } },
        ["acos"] = { ["arguments"] = { "target" } },
        ["atan"] = { ["arguments"] = { "target" } },
        ["sinh"] = { ["arguments"] = { "target" } },
        ["cosh"] = { ["arguments"] = { "target" } },
        ["tanh"] = { ["arguments"] = { "target" } },
        ["ln"] = { ["arguments"] = { "target" } },
        ["log"] = { ["arguments"] = { "base", "target" } },
        ["pi"] = { ["arguments"] = {} },
        ["euler"] = { ["arguments"] = {} },
        ["rad"] = { ["arguments"] = { "target" } },
        ["deg"] = { ["arguments"] = { "target" } },
        ["base"] = { ["arguments"] = { "target", "targetBase" } },
        ["inf"] = { ["arguments"] = {} }
      },
      ["string"] = {
        ["join"] = { ["arguments"] = { "targetA", "targetB" } },
        ["length"] = { ["arguments"] = { "target" } },
        ["letter"] = { ["arguments"] = { "target", "pos" } },
        ["contains"] = { ["arguments"] = { "target", "patt" } },
        ["upper"] = { ["arguments"] = { "target" } },
        ["lower"] = { ["arguments"] = { "target" } },
        ["replace"] = { ["arguments"] = { "target", "patt", "repl", "amou" } },
        ["split"] = { ["arguments"] = { "target", "sep" } },
        ["find"] = { ["arguments"] = { "target", "patt" } }
      },
      ["control"] = {
        ["type"] = { ["arguments"] = { "target" } },
        ["wait"] = { ["arguments"] = { "target" } },
        ["tonumber"] = { ["arguments"] = { "target" } },
        ["tostring"] = { ["arguments"] = { "target" } }
      },
      ["list"] = {
        ["item"] = { ["arguments"] = { "list", "pos" } },
        ["add"] = { ["arguments"] = { "list", "target" } },
        ["insert"] = { ["arguments"] = { "list", "y", "pos" } },
        ["length"] = { ["arguments"] = { "list" } },
        ["position"] = { ["arguments"] = { "list", "target" } },
        ["delete"] = { ["arguments"] = { "list", "pos" } },
        ["replace"] = { ["arguments"] = { "list", "pos", "repl" } },
        ["contains"] = { ["arguments"] = { "list", "y" } },
        ["clear"] = { ["arguments"] = { "list" } },
        ["concatenate"] = { ["arguments"] = { "list", "sep" } }
      },
      ["instance"] = {
        ["new"] = { ["arguments"] = { "target" } },
        ["destroy"] = { ["arguments"] = { "target" } }
      }
    }

    local classes = {}
    local instances = {}

    local scopes = {}
    local in_scopes = {}

    local global_variables = {}

    function Scopes_new()
      table.insert(in_scopes, {})
    end

    function Scopes_add(element, value)
      if not scopes[element] then
        table.insert(in_scopes[#in_scopes], element)
      end
      scopes[element] = value
    end

    function Scopes_remove()
      for i, v in pairs(in_scopes[#in_scopes]) do
        scopes[v] = nil
      end
      table.remove(in_scopes, #in_scopes)
    end

    function Clamp(value, minimum, maximum)
      if value < minimum then
        return minimum
      end
      if value > maximum then
        return maximum
      end

      return value
    end

    function EqualLists(list1, list2)
      for i, v in pairs(list1) do
        if list1[i] ~= list2[i] then
          return false
        end
      end
      return true
    end

    function GetListLength(list)
      local index = 0
      for i, v in pairs(list) do
        index = index + 1
      end

      return index
    end

    function GetToken(value)
      local return_value = "whitespace"
      local s, e = pcall(function()
        if Find_in_array(binary_operators, value) > 0 then
          return_value = "binary operator"
        elseif Find_in_array(unary_operators, value) > 0 then
          return_value = "unary operator"
        elseif value == "(" then
          return_value = "open parenthesis"
        elseif value == ")" then
          return_value = "close parenthesis"
        elseif value == "=" then
          return_value = "equals"
        elseif tonumber(value) or tostring(string.sub(value, 1, 2)) == "0x" or tostring(string.sub(value, 1, 2)) == "0b" then
          return_value = "number"
        elseif (string.sub(value, 1, 1) == '"' and string.sub(value, #value, #value) == '"') or (string.sub(value, 1, 1) == "'" and string.sub(value, #value, #value) == "'") then
          return_value = "string"
        elseif value == "true" or value == "false" then
          return_value = "bool"
        elseif value == "null" or value == nil then
          return_value = "null"
        elseif Find_in_array(keywords, value) > 0 then
          return_value = "keyword"
        elseif value ~= nil and value ~= "" and value ~= "\n" and value ~= " " then
          return_value = "identifier"
        end
      end)

      return return_value
    end

    local data_types = { "string", "number", "bool", "list", "function", "class", "function", "null", "any" }

    function GetDataType(value, interpreted)
      if GetToken(interpreted) == "string" then
        return "string"
      elseif GetToken(interpreted) == "number" then
        return "number"
      elseif GetToken(interpreted) == "bool" then
        return "bool"
      elseif type(interpreted) == "table" then
        return "list"
      elseif GetToken(interpreted) == "null" or interpreted == nil then
        return "null"
      elseif classes[value["value"]] then
        return "class"
      elseif instances[value["value"]] then
        return "instance"
      elseif functions[value["value"]] then
        return "function"
      end
    end

    function HasEnd(value)
      if value == "if" or value == "define" or value == "class" or value == "repeat" or value == "while" or value == "for" then
        return true
      end
      return false
    end

    function Wait(seconds)
      local start = os.time()
      repeat until os.time() > start + seconds
    end

    function Find_in_array(array, value)
      for i, v in pairs(array) do
        if value == "any thing" then
          return i
        end
        if type(value) == "table" and type(v) == "table" then
          for j, k in pairs(value) do
            if k == "any thing" then
              value[j] = v[j]
            end
          end

          if EqualLists(v, value) then
            return i
          end
        end
        if v == value then
          return i
        end
      end
      return 0
    end

    function Find_index_in_array(array, index)
      for i, v in pairs(array) do
        if i == index then
          return true
        end
      end
      return false
    end

    function Round(value)
      if value then
        if value - math.floor(value) < math.ceil(value) - value then
          return math.floor(value)
        else
          return math.ceil(value)
        end
      end
    end

    function RemoveMagic(char)
      if char == "(" or char == ")" or char == "." or char == "[" or char == "^" or char == "$" or char == "%" then
        return "%%" .. char
      else
        return char
      end
    end

    local hex_chars = " 0123456789ABCDEF"
    local bin_chars = " 01"

    function CheckBase(value, base, chars)
      value = tostring(value)
      if string.sub(value, 2, 2) ~= base or string.sub(value, 1, 1) ~= "0" then
        return false
      end

      value = string.sub(value, 3, #value)
      for i = 1, #value do
        local char = string.sub(value, i, i)
        if not string.find(chars, RemoveMagic(string.upper(char))) then
          return false
        else
          if string.find(chars, RemoveMagic(string.upper(char))) == 1 then
            return false
          end
        end
      end

      return true
    end

    function IsBase(char, chars)
      if not string.find(chars, RemoveMagic(string.upper(char))) then
        return false
      else
        if string.find(chars, RemoveMagic(string.upper(char))) == 1 then
          return false
        end
      end

      return true
    end

    local hex_table = {
      ["0"] = 0,
      ["1"] = 1,
      ["2"] = 2,
      ["3"] = 3,
      ["4"] = 4,
      ["5"] = 5,
      ["6"] = 6,
      ["7"] = 7,
      ["8"] = 8,
      ["9"] = 9,
      ["A"] = 10,
      ["B"] = 11,
      ["C"] = 12,
      ["D"] = 13,
      ["E"] = 14,
      ["F"] = 15
    }

    local bin_table = { ["0"] = 0, ["1"] = 1 }

    function ConvertBases(target)
      if tostring(string.sub(target, 1, 1)) ~= "0" then
        return target
      end

      local base
      if string.sub(target, 2, 2) == "x" then
        base = hex_table
      elseif string.sub(target, 2, 2) == "b" then
        base = bin_table
      else
        return target
      end

      target = string.sub(target, 3, #target)

      local result = 0
      for i = 1, #target do
        local char = string.sub(target, i, i)

        result = result + base[char] * math.pow(GetListLength(base), #target - i)
      end

      return result
    end

    local code_chunks = {}

    local chunk = ""
    local open_string = ""

    local allowed_chars = " abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
    local string_index = 0
    local skip_index = 0
    for i = 1, #code do
      if skip_index == i then
        goto continue
      end

      local char = string.sub(code, i, i)

      if char == '"' and open_string == "" then
        if chunk ~= "" then
          table.insert(code_chunks, chunk)
        end
        chunk = ""

        string_index = i
        open_string = '"'
      elseif char == "'" and open_string == "" then
        if chunk ~= "" then
          table.insert(code_chunks, chunk)
        end
        chunk = ""

        string_index = i
        open_string = "'"
      end

      if char == " " or not string.find(allowed_chars, RemoveMagic(char)) then
        if open_string ~= "" then
          chunk = chunk .. char
        else
          if not (char == "-" and tonumber(string.sub(code, i + 1, i + 1)) and not tonumber(string.sub(code, i - 1, i - 1))) then
            if chunk ~= "" then
              table.insert(code_chunks, chunk)
            end
            if char ~= " " then
              table.insert(code_chunks, char)
            end
            chunk = ""
          else
            if chunk ~= "" then
              table.insert(code_chunks, chunk)
            end
            chunk = "-"
          end
        end
      else
        if string.find(allowed_chars, RemoveMagic(char)) == 1 then
          if chunk ~= "" then
            table.insert(code_chunks, chunk)
          end
          if char ~= " " then
            table.insert(code_chunks, char)
          end
          chunk = ""

          goto continue
        end
        if open_string ~= "" then
          chunk = chunk .. char
        else
          if tonumber(char) and not tonumber(string.sub(code, i + 1, i + 1)) then
            chunk = chunk .. char
            if string.sub(code, i + 1, i + 1) == "." and tonumber(string.sub(code, i + 2, i + 2)) then
              chunk = chunk .. string.sub(code, i + 1, i + 1)
              skip_index = i + 1
            else
              if tostring(chunk) == "0" then
                if string.sub(code, i + 1, i + 1) ~= "x" and string.sub(code, i + 1, i + 1) ~= "b" then
                  table.insert(code_chunks, chunk)
                  chunk = ""
                end
              else
                chunk = string.sub(tostring(chunk), 1, #tostring(chunk) - 1)
                if (not CheckBase(chunk, "x", hex_chars)) and (not CheckBase(chunk, "b", bin_chars)) then
                  table.insert(code_chunks, chunk .. char)
                  chunk = ""
                else
                  if CheckBase(chunk, "b", bin_chars) then
                    if not string.find(bin_chars, char) then
                      table.insert(code_chunks, chunk)
                      chunk = char
                    else
                      if string.find(bin_chars, char) == 1 then
                        table.insert(code_chunks, chunk)
                        chunk = char
                      else
                        chunk = chunk .. char
                      end
                    end
                  else
                    chunk = chunk .. char
                  end
                end
              end
            end
          else
            if string.sub(tostring(chunk), 1, 1) == "0" and string.sub(tostring(chunk), 2, 2) == "x" then
              if IsBase(char, hex_chars) then
                chunk = chunk .. char
              else
                table.insert(code_chunks, chunk)
                chunk = char
              end
            elseif string.sub(tostring(chunk), 1, 1) == "0" and string.sub(tostring(chunk), 2, 2) == "b" then
              if IsBase(char, bin_chars) then
                chunk = chunk .. char
              else
                table.insert(code_chunks, chunk)
                chunk = char
              end
            else
              chunk = chunk .. char
            end
          end
        end
      end

      if char == '"' and open_string == '"' and string_index ~= i then
        if chunk ~= "" then
          table.insert(code_chunks, chunk)
        end
        chunk = ""

        open_string = ""
      elseif char == "'" and open_string == "'" and string_index ~= i then
        if chunk ~= "" then
          table.insert(code_chunks, chunk)
        end
        chunk = ""

        open_string = ""
      end

      ::continue::
    end
    if chunk ~= "" then
      table.insert(code_chunks, chunk)
    end

    local chunk_index = 0
    while not (chunk_index > #code_chunks) do
      chunk_index = chunk_index + 1

      if chunk_index > #code_chunks then
        break
      end

      if GetToken(code_chunks[chunk_index]) == "number" and string.sub(code_chunks[chunk_index], 1, 2) ~= "0x" and string.sub(code_chunks[chunk_index], 1, 2) ~= "0b" then
        code_chunks[chunk_index] = tonumber(code_chunks[chunk_index])
      end
      if GetToken(code_chunks[chunk_index]) == "whitespace" then
        table.remove(code_chunks, chunk_index)
        chunk_index = chunk_index - 1
      end
    end

    if #code == 0 then
      return
    end

    if Find_in_array(code_chunks, "#") > 0 then
      repeat
        local pos = Find_in_array(code_chunks, "#")
        table.remove(code_chunks, pos)

        if Find_in_array(code_chunks, "#") == 0 then
          print("expected '#' to close comment")
          error(0)
        end

        for i = pos, Find_in_array(code_chunks, "#") do
          table.remove(code_chunks, pos)
        end
      until Find_in_array(code_chunks, "#") == 0
    end

    function Parse_terms(tokens)
      local left = Parse_factors(tokens)

      if tokens[1] == "+" or tokens[1] == "-" then
        local type = "sum"
        if tokens[1] == "-" then
          type = "difference"
        end
        table.remove(tokens, 1)

        return { ["type"] = type, ["left"] = left, ["right"] = Parse_terms(tokens) }
      end

      return left
    end

    function Parse_factors(tokens)
      local left = Parse_logic(tokens)

      if tokens[1] == "*" or tokens[1] == "/" or tokens[1] == "mod" then
        local type = "product"
        if tokens[1] == "/" then
          type = "quotient"
        elseif tokens[1] == "mod" then
          type = "modulo"
        end
        table.remove(tokens, 1)

        return { ["type"] = type, ["left"] = left, ["right"] = Parse_factors(tokens) }
      end
      return left
    end

    function Parse_logic(tokens)
      local left = Parse_parentheses(tokens)

      if tokens[1] == "=" then
        table.remove(tokens, 1)

        return { ["type"] = "equality", ["left"] = left, ["right"] = Parse_logic(tokens) }
      elseif tostring(tokens[1]) .. tostring(tokens[2]) == "<=" then
        table.remove(tokens, 1)
        table.remove(tokens, 1)

        return { ["type"] = "inferior equal", ["left"] = left, ["right"] = Parse_logic(tokens) }
      elseif tostring(tokens[1]) .. tostring(tokens[2]) == ">=" then
        table.remove(tokens, 1)
        table.remove(tokens, 1)

        return { ["type"] = "superior equal", ["left"] = left, ["right"] = Parse_logic(tokens) }
      elseif tokens[1] == "<" then
        table.remove(tokens, 1)

        return { ["type"] = "inferiority", ["left"] = left, ["right"] = Parse_logic(tokens) }
      elseif tokens[1] == ">" then
        table.remove(tokens, 1)

        return { ["type"] = "superiority", ["left"] = left, ["right"] = Parse_logic(tokens) }
      elseif tokens[1] == "or" then
        table.remove(tokens, 1)

        return { ["type"] = "or gate", ["left"] = left, ["right"] = Parse_logic(tokens) }
      elseif tokens[1] == "and" then
        table.remove(tokens, 1)

        return { ["type"] = "and gate", ["left"] = left, ["right"] = Parse_logic(tokens) }
      elseif tokens[1] == "xor" then
        table.remove(tokens, 1)

        return { ["type"] = "xor gate", ["left"] = left, ["right"] = Parse_logic(tokens) }
      elseif left["value"] == "not" then
        return { ["type"] = "not gate", ["right"] = Parse_logic(tokens) }
      end
      return left
    end

    function Parse_parentheses(tokens)
      if GetToken(tokens[1]) == "open parenthesis" then
        table.remove(tokens, 1)
        local terms = Parse_terms(tokens)
        if GetToken(tokens[1]) ~= "close parenthesis" then
          print("expected ')', got " .. Tokenize(tokens[1]))
          error(0)
        end

        table.remove(tokens, 1)
        return terms
      end
      return Parse_literal(tokens)
    end

    function Parse_literal(tokens)
      if #tokens == 0 then
        print("expected number, string, bool or identifier, got null")
        error(0)
      end

      local literal = tokens[1]
      table.remove(tokens, 1)

      if literal == "{" then
        local list = {}
        while tokens[1] ~= "}" do
          if tokens[1] == nil then
            print("expected }")
            error(0)
          end
          if GetToken(tokens[1]) ~= "identifier" and GetToken(tokens[1]) ~= "number" and GetToken(tokens[1]) ~= "string" and GetToken(tokens[1]) ~= "bool" and GetToken(tokens[1]) ~= "null" and GetToken(tokens[1]) ~= "unary operator" and literal ~= "{" then
            print("expected number, string, bool, identifier or unary operator, got " .. Tokenize(tokens[1]))
            error(0)
          end
          if tokens[2] == ":" then
            local dictValue = Parse(tokens, {}, false)[1]
            table.remove(tokens, 1)

            if GetToken(tokens[1]) ~= "identifier" and GetToken(tokens[1]) ~= "number" and GetToken(tokens[1]) ~= "string" and GetToken(tokens[1]) ~= "bool" and GetToken(tokens[1]) ~= "null" and GetToken(tokens[1]) ~= "unary operator" and literal ~= "{" then
              print("expected identifier, number, string, bool, identifier or unary operator, got " ..
                Tokenize(tokens[1]))
              error(0)
            end

            list[dictValue["value"]] = Parse(tokens, {}, false)[1]
          else
            table.insert(list, Parse(tokens, {}, false)[1])
          end

          if tokens[1] == "," then
            table.remove(tokens, 1)
          elseif tokens[1] ~= "}" then
            print("expected ',' or '}', got " .. Tokenize(tokens[1]))
            error(0)
          end
        end
        table.remove(tokens, 1)
        return { ["type"] = "list", ["value"] = list }
      elseif GetToken(literal) == "identifier" or GetToken(literal) == "number" or GetToken(literal) == "string" or GetToken(literal) == "bool" or GetToken(literal) == "null" or GetToken(literal) == "unary operator" then
        if GetToken(literal) == "identifier" and GetToken(tokens[1]) == "open parenthesis" then
          table.remove(tokens, 1)

          local arguments = {}

          if GetToken(tokens[1]) ~= "close parenthesis" then
            repeat
              if GetToken(tokens[1]) ~= "identifier" and GetToken(tokens[1]) ~= "number" and GetToken(tokens[1]) ~= "string" and GetToken(tokens[1]) ~= "bool" and GetToken(tokens[1]) ~= "null" and GetToken(tokens[1]) ~= "unary operator" and GetToken(tokens[1]) ~= "open parenthesis" and literal ~= "{" then
                print("expected number, string, bool, identifier or unary operator, got " .. tokens[1])
                error(0)
              end
              table.insert(arguments, Parse(tokens, {}, false)[1])

              if tokens[1] ~= "," and tokens[1] ~= ")" then
                if tokens[1] ~= ")" then
                  print("expected ')', got " .. Tokenize(tokens[1]))
                  error(0)
                end
                print("expected ',', got " .. Tokenize(tokens[1]))
                error(0)
              end
              if tokens[1] ~= ")" then
                table.remove(tokens, 1)
              end
            until GetToken(tokens[1]) ~= "identifier" and GetToken(tokens[1]) ~= "number" and GetToken(tokens[1]) ~= "string" and GetToken(tokens[1]) ~= "bool" and GetToken(tokens[1]) ~= "null" and GetToken(tokens[1]) ~= "unary operator" and literal ~= "{" and tokens[1] ~= ","
          end

          if GetToken(tokens[1]) ~= "close parenthesis" then
            print("expected ')', got " .. Tokenize(tokens[1]))
            error(0)
          end
          table.remove(tokens, 1)

          return { ["type"] = GetToken(literal), ["value"] = literal, ["arguments"] = arguments }
        end

        if GetToken(literal) == "identifier" and tokens[1] == "." then
          table.remove(tokens, 1)
          return { ["type"] = GetToken(literal), ["value"] = literal, ["path"] = Parse_literal(tokens) }
        end

        return { ["type"] = GetToken(literal), ["value"] = literal }
      else
        print("expected number, string, bool, identifier or unary operator, got " .. Tokenize(literal))
        error(0)
      end
    end

    -- Keywords

    function P_set(tokens, global)
      if GetToken(tokens[1]) ~= "identifier" then
        print("expected identifier, got " .. Tokenize(tokens[1]))
        error(0)
      end
      local variable_name = tokens[1]
      table.remove(tokens, 1)

      if tokens[1] ~= "to" then
        print("expected 'to', got " .. Tokenize(tokens[1]))
        error(0)
      end
      table.remove(tokens, 1)

      local type = "variable declaration"
      if global then
        type = "global declaration"
      end

      return { ["type"] = type, ["variable"] = variable_name, ["value"] = Parse(tokens, {}, false)[1] }
    end

    function P_change(tokens)
      if GetToken(tokens[1]) ~= "identifier" then
        print("expected identifier, got " .. Tokenize(tokens[1]))
        error(0)
      end
      local variable_name = tokens[1]
      table.remove(tokens, 1)

      if tokens[1] ~= "by" then
        print("expected 'by', got " .. Tokenize(tokens[1]))
        error(0)
      end
      table.remove(tokens, 1)

      local type = "variable change"

      return { ["type"] = type, ["variable"] = variable_name, ["value"] = Parse(tokens, {}, false)[1] }
    end

    function P_define(tokens)
      if GetToken(tokens[1]) ~= "identifier" then
        print("expected identifier, got " .. Tokenize(tokens[1]))
        error(0)
      end
      local function_name = tokens[1]
      table.remove(tokens, 1)

      if GetToken(tokens[1]) ~= "open parenthesis" then
        print("expected '(', got " .. Tokenize(tokens[1]))
        error(0)
      end
      table.remove(tokens, 1)

      local function_arguments = {}

      if GetToken(tokens[1]) ~= "close parenthesis" then
        repeat
          if GetToken(tokens[1]) ~= "identifier" then
            print("expected identifier, got " .. Tokenize(tokens[1]))
            error(0)
          end
          local argument = tokens[1]
          table.remove(tokens, 1)

          if tokens[1] == "~" then
            table.insert(function_arguments, { ["token"] = argument, ["data types"] = P_SDT(tokens) })
          else
            table.insert(function_arguments, { ["token"] = argument, ["data types"] = { "any" } })
          end

          if tokens[1] ~= "," and tokens[1] ~= ")" then
            print("expected ',', got " .. Tokenize(tokens[1]))
            error(0)
          end
          if tokens[1] ~= ")" then
            table.remove(tokens, 1)
          end
        until GetToken(tokens[1]) ~= "identifier" and tokens[1] ~= ","
      end

      if GetToken(tokens[1]) ~= "close parenthesis" then
        print("expected ')', got " .. Tokenize(tokens[1]))
        error(0)
      end
      table.remove(tokens, 1)

      local func_data_types

      if tokens[1] == "~" then
        func_data_types = P_SDT(tokens)
      end

      local inFunction = {}

      if Find_in_array(tokens, "end") == 0 then
        print("expected 'end' to close function")
        error(0)
      end

      local scope_count = 0
      local scope_index = 0
      while true do
        scope_index = scope_index + 1
        if HasEnd(tokens[scope_index]) then
          scope_count = scope_count + 1
        end
        if tokens[scope_index] == "end" then
          if scope_count == 0 then
            break
          end
          scope_count = scope_count - 1
        end
        table.insert(inFunction, tokens[scope_index])
      end

      for i = 1, #inFunction + 1 do
        table.remove(tokens, 1)
      end

      if func_data_types then
        return {
          ["type"] = "function declaration",
          ["function"] = function_name,
          ["arguments"] = function_arguments,
          ["data types"] = data_types,
          ["body"] = Parse(inFunction, {}, true)
        }
      else
        return {
          ["type"] = "function declaration",
          ["function"] = function_name,
          ["arguments"] = function_arguments,
          ["data types"] = { "any" },
          ["body"] = Parse(inFunction, {}, true)
        }
      end
    end

    function P_class(tokens)
      if GetToken(tokens[1]) ~= "identifier" then
        print("expected identifier, got " .. Tokenize(tokens[1]))
        error(0)
      end
      local class_name = tokens[1]
      table.remove(tokens, 1)

      if GetToken(tokens[1]) ~= "open parenthesis" then
        print("expected '(', got " .. Tokenize(tokens[1]))
        error(0)
      end
      table.remove(tokens, 1)

      local class_arguments = {}

      if GetToken(tokens[1]) ~= "close parenthesis" then
        repeat
          if GetToken(tokens[1]) ~= "identifier" then
            print("expected identifier, got " .. Tokenize(tokens[1]))
            error(0)
          end
          table.insert(class_arguments, tokens[1])

          table.remove(tokens, 1)
          if tokens[1] ~= "," and tokens[1] ~= ")" then
            print("expected ',', got " .. Tokenize(tokens[1]))
            error(0)
          end
          if tokens[1] ~= ")" then
            table.remove(tokens, 1)
          end
        until GetToken(tokens[1]) ~= "identifier" and tokens[1] ~= ","
      end

      if GetToken(tokens[1]) ~= "close parenthesis" then
        print("expected ')', got " .. Tokenize(tokens[1]))
        error(0)
      end
      table.remove(tokens, 1)

      local inClass = {}

      if Find_in_array(tokens, "end") == 0 then
        print("expected end, got " .. Tokenize(tokens[1]))
        error(0)
      end

      local scope_count = 0
      local scope_index = 0
      while true do
        scope_index = scope_index + 1
        if HasEnd(tokens[scope_index]) then
          scope_count = scope_count + 1
        end
        if tokens[scope_index] == "end" then
          if scope_count == 0 then
            break
          end
          scope_count = scope_count - 1
        end
        table.insert(inClass, tokens[scope_index])
      end

      for i = 1, #inClass + 1 do
        table.remove(tokens, 1)
      end

      return {
        ["type"] = "class declaration",
        ["class"] = class_name,
        ["arguments"] = class_arguments,
        ["body"] = Parse(inClass, {}, true)
      }
    end

    function P_if(tokens)
      local condition = Parse(tokens, {}, false)[1]
      if tokens[1] ~= "then" then
        print("expected 'then', got " .. Tokenize(tokens[1]))
        error(0)
      end
      table.remove(tokens, 1)

      local inStatement = {}
      local elseStatement = {}
      local elifStatement = {}
      if Find_in_array(tokens, "end") == 0 then
        print("expected 'end' to close if statement")
        error(0)
      end
      if Find_in_array(tokens, "elif") ~= 0 then
        if Find_in_array(tokens, "elif") < Find_in_array(tokens, "end") then
          local scope_count = 0
          local scope_index = 0

          local found_elif = true
          while true do
            scope_index = scope_index + 1
            if HasEnd(tokens[scope_index]) then
              scope_count = scope_count + 1
            end
            if tokens[scope_index] == "elif" then
              if scope_count == 0 then
                break
              end
              scope_count = scope_count - 1
            end
            if scope_index > Find_in_array(tokens, "end") then
              found_elif = false
              break
            end
          end

          if found_elif then
            for i = 1, scope_index - 1 do
              table.insert(inStatement, tokens[i])
            end
            for i = 1, #inStatement + 1 do
              table.remove(tokens, 1)
            end

            local scope_count = 0
            local scope_index = 0

            table.insert(elifStatement, "if")
            while true do
              scope_index = scope_index + 1
              if HasEnd(tokens[scope_index]) then
                scope_count = scope_count + 1
              end
              if tokens[scope_index] == "end" then
                if scope_count == 0 then
                  table.insert(elifStatement, tokens[scope_index])
                  break
                end
                scope_count = scope_count - 1
              end

              table.insert(elifStatement, tokens[scope_index])
            end

            for i = 1, #elifStatement - 1 do
              table.remove(tokens, 1)
            end

            return {
              ["type"] = "if statement",
              ["condition"] = condition,
              ["body"] = Parse(inStatement, {}, true),
              ["else body"] = Parse(elifStatement, {}, true)
            }
          end
        end
      elseif Find_in_array(tokens, "else") ~= 0 then
        if Find_in_array(tokens, "else") < Find_in_array(tokens, "end") then
          local scope_count = 0
          local scope_index = 0

          local found_else = true
          while true do
            scope_index = scope_index + 1
            if HasEnd(tokens[scope_index]) then
              scope_count = scope_count + 1
            end
            if tokens[scope_index] == "else" then
              if scope_count == 0 then
                break
              end
              scope_count = scope_count - 1
            end
            if scope_index > Find_in_array(tokens, "else") then
              found_else = false
              break
            end
          end

          if found_else then
            for i = 1, scope_index - 1 do
              table.insert(inStatement, tokens[i])
            end
            for i = 1, #inStatement + 1 do
              table.remove(tokens, 1)
            end

            local scope_count = 0
            local scope_index = 0
            while true do
              scope_index = scope_index + 1
              if HasEnd(tokens[scope_index]) then
                scope_count = scope_count + 1
              end
              if tokens[scope_index] == "end" then
                if scope_count == 0 then
                  break
                end
                scope_count = scope_count - 1
              end
              table.insert(elseStatement, tokens[scope_index])
            end

            for i = 1, #elseStatement + 1 do
              table.remove(tokens, 1)
            end

            return {
              ["type"] = "if statement",
              ["condition"] = condition,
              ["body"] = Parse(inStatement, {}, true),
              ["else body"] = Parse(elseStatement, {}, true)
            }
          end
        end
      end

      local scope_count = 0
      local scope_index = 0
      while true do
        scope_index = scope_index + 1
        if HasEnd(tokens[scope_index]) then
          scope_count = scope_count + 1
        end
        if tokens[scope_index] == "end" then
          if scope_count == 0 then
            break
          end
          scope_count = scope_count - 1
        end
        table.insert(inStatement, tokens[scope_index])
      end

      for i = 1, #inStatement + 1 do
        table.remove(tokens, 1)
      end

      return { ["type"] = "if statement", ["condition"] = condition, ["body"] = Parse(inStatement, {}, true) }
    end

    function P_repeat(tokens)
      if tokens[1] == "until" then
        table.remove(tokens, 1)

        local condition = Parse(tokens, {}, false)[1]

        local inLoop = {}
        if Find_in_array(tokens, "end") == 0 then
          print("expected 'end' to close repeat loop")
        end

        local scope_count = 0
        local scope_index = 0
        while true do
          scope_index = scope_index + 1
          if HasEnd(tokens[scope_index]) then
            scope_count = scope_count + 1
          end
          if tokens[scope_index] == "end" then
            if scope_count == 0 then
              break
            end
            scope_count = scope_count - 1
          end
          table.insert(inLoop, tokens[scope_index])
        end

        for i = 1, #inLoop + 1 do
          table.remove(tokens, 1)
        end

        return { ["type"] = "repeat until loop", ["condition"] = condition, ["body"] = Parse(inLoop, {}, true) }
      else
        local amount = Parse(tokens, {}, false)[1]

        local inLoop = {}
        if Find_in_array(tokens, "end") == 0 then
          print("expected 'end' to close repeat loop")
          error(0)
        end

        local scope_count = 0
        local scope_index = 0
        while true do
          scope_index = scope_index + 1
          if HasEnd(tokens[scope_index]) then
            scope_count = scope_count + 1
          end
          if tokens[scope_index] == "end" then
            if scope_count == 0 then
              break
            end
            scope_count = scope_count - 1
          end
          table.insert(inLoop, tokens[scope_index])
        end

        for i = 1, #inLoop + 1 do
          table.remove(tokens, 1)
        end


        return { ["type"] = "repeat amount loop", ["amount"] = amount, ["body"] = Parse(inLoop, {}, true) }
      end
    end

    function P_while(tokens)
      local condition = Parse(tokens, {}, false)[1]
      if tokens[1] ~= "do" then
        print("expected 'do', got " .. Tokenize(tokens[1]))
        error(0)
      end
      table.remove(tokens, 1)

      local inLoop = {}
      if Find_in_array(tokens, "end") == 0 then
        print("expected 'end' to close while loop")
        error(0)
      end

      local scope_count = 0
      local scope_index = 0
      while true do
        scope_index = scope_index + 1
        if HasEnd(tokens[scope_index]) then
          scope_count = scope_count + 1
        end
        if tokens[scope_index] == "end" then
          if scope_count == 0 then
            break
          end
          scope_count = scope_count - 1
        end
        table.insert(inLoop, tokens[scope_index])
      end

      for i = 1, #inLoop + 1 do
        table.remove(tokens, 1)
      end

      return { ["type"] = "while loop", ["condition"] = condition, ["body"] = Parse(inLoop, {}, true) }
    end

    function P_for(tokens)
      if tokens[1] ~= "each" then
        print("expected 'each', got " .. Tokenize(tokens[1]))
        error(0)
      end
      table.remove(tokens, 1)

      if GetToken(tokens[1]) ~= "identifier" then
        print("expected identifier, got " .. Tokenize(tokens[1]))
        error(0)
      end
      local counter = Parse(tokens, {}, false)[1]

      local start
      local value
      if tokens[1] == ":" then
        table.remove(tokens, 1)
        start = Parse(tokens, {}, false)[1]
      elseif tokens[1] == "item" then
        table.remove(tokens, 1)
        if GetToken(tokens[1]) ~= "identifier" then
          print("expected identifier, got " .. Tokenize(tokens[1]))
          error(0)
        end
        value = Parse(tokens, {}, false)[1]
      else
        start = 1
      end

      if tokens[1] ~= "in" then
        print("expected 'in', got " .. Tokenize(tokens[1]))
        error(0)
      end
      table.remove(tokens, 1)

      local goal = Parse(tokens, {}, false)[1]

      if tokens[1] ~= "do" then
        print("expected 'do', got " .. Tokenize(tokens[1]))
        error(0)
      end
      table.remove(tokens, 1)

      local inLoop = {}
      if Find_in_array(tokens, "end") == 0 then
        print("expected 'end' to close for loop")
        error(0)
      end

      local scope_count = 0
      local scope_index = 0
      while true do
        scope_index = scope_index + 1
        if HasEnd(tokens[scope_index]) then
          scope_count = scope_count + 1
        end
        if tokens[scope_index] == "end" then
          if scope_count == 0 then
            break
          end
          scope_count = scope_count - 1
        end
        table.insert(inLoop, tokens[scope_index])
      end

      for i = 1, #inLoop + 1 do
        table.remove(tokens, 1)
      end

      if value then
        return {
          ["type"] = "for loop",
          ["counter"] = counter,
          ["value"] = value,
          ["list"] = goal,
          ["body"] = Parse(inLoop,
            {}, true)
        }
      end
      return {
        ["type"] = "for loop",
        ["counter"] = counter,
        ["start"] = start,
        ["goal"] = goal,
        ["body"] = Parse(inLoop,
          {}, true)
      }
    end

    function P_SDT(tokens)
      if tokens[1] ~= "~" then
        return nil
      end
      table.remove(tokens, 1)

      if tokens[1] ~= ">" then
        print("expected '>', got " .. Tokenize(tokens[1]))
        error(0)
      end
      table.remove(tokens, 1)

      if tokens[1] ~= "<" then
        print("expected '<', got " .. Tokenize(tokens[1]))
        error(0)
      end
      table.remove(tokens, 1)

      if Find_in_array(tokens, ">") == 0 then
        print("expected '>' to close strict data type")
        error(0)
      end

      local SDTs = {}

      while tokens[1] ~= ">" do
        if Find_in_array(data_types, tokens[1]) == 0 then
          print("unknown data type " .. Tokenize(tokens[1]))
          error(0)
        end
        table.insert(SDTs, tokens[1])
        table.remove(tokens, 1)

        if tokens[1] ~= ">" then
          if tokens[1] ~= "|" then
            print("expected '|', got " .. Tokenize(tokens[1]))
            error(0)
          end
        else
          table.remove(tokens, 1)
          break
        end
        table.remove(tokens, 1)
      end

      return SDTs
    end

    -- Parsing/Interpreting

    function Parse(tokens, AST, recursion)
      if GetToken(tokens[1]) == "keyword" then
        local keyword = tokens[1]
        table.remove(tokens, 1)

        if keyword == "set" or keyword == "global" then
          table.insert(AST, P_set(tokens, keyword == "global"))
        elseif keyword == "change" then
          table.insert(AST, P_change(tokens))
        elseif keyword == "define" then
          table.insert(AST, P_define(tokens))
        elseif keyword == "class" then
          table.insert(AST, P_class(tokens))
        elseif keyword == "if" then
          table.insert(AST, P_if(tokens))
        elseif keyword == "repeat" then
          table.insert(AST, P_repeat(tokens))
        elseif keyword == "while" then
          table.insert(AST, P_while(tokens))
        elseif keyword == "for" then
          table.insert(AST, P_for(tokens))
        else
          if keyword == "return" or keyword == "skip" or keyword == "stop" or keyword == "require" then
            if keyword == "return" or keyword == "require" then
              table.insert(AST, { ["type"] = "keyword", ["keyword"] = keyword, ["value"] = Parse(tokens, {}, false)[1] })
            else
              table.insert(AST, { ["type"] = "keyword", ["keyword"] = keyword })
            end
          else
            table.insert(AST, Parse_terms(tokens))
          end
        end
      else
        table.insert(AST, Parse_terms(tokens))
      end
      if recursion and #tokens > 0 then
        return Parse(tokens, AST, true)
      end
      return AST
    end

    local current_path = functions
    local last_path = {}

    Scopes_new()

    local function copy(obj, seen)
      if type(obj) ~= 'table' then return obj end
      if seen and seen[obj] then return seen[obj] end
      local s = seen or {}
      local res = setmetatable({}, getmetatable(obj))
      s[obj] = res
      for k, v in pairs(obj) do res[copy(k, s)] = copy(v, s) end
      return res
    end

    function Interpret(node)
      local return_value = nil
      if node == nil then
        return nil
      end

      if GetToken(node) == "string" or GetToken(node) == "number" or GetToken(node) == "bool" then
        -- String, Number or Bool
        return node
      elseif node["type"] == "sum" then
        -- Sum
        local left = Interpret(node["left"])
        local right = Interpret(node["right"])
        if GetToken(left) ~= "number" then
          print("expected number, got " .. Tokenize(left))
          error(0)
        end
        if GetToken(right) ~= "number" then
          print("expected number, got " .. Tokenize(right))
          error(0)
        end

        return tonumber(ConvertBases(left)) + tonumber(ConvertBases(right))
      elseif node["type"] == "difference" then
        -- Difference
        local left = Interpret(node["left"])
        local right = Interpret(node["right"])
        if GetToken(left) ~= "number" then
          print("expected number, got " .. Tokenize(left))
          error(0)
        end
        if GetToken(right) ~= "number" then
          print("expected number, got " .. Tokenize(right))
          error(0)
        end

        return tonumber(ConvertBases(left)) - tonumber(ConvertBases(right))
      elseif node["type"] == "product" then
        -- Product
        local left = Interpret(node["left"])
        local right = Interpret(node["right"])
        if GetToken(left) ~= "number" then
          print("expected number, got " .. Tokenize(left))
          error(0)
        end
        if GetToken(right) ~= "number" then
          print("expected number, got " .. Tokenize(right))
          error(0)
        end

        return tonumber(ConvertBases(left)) * tonumber(ConvertBases(right))
      elseif node["type"] == "quotient" then
        -- Quotient
        local left = Interpret(node["left"])
        local right = Interpret(node["right"])
        if GetToken(left) ~= "number" then
          print("expected number, got " .. Tokenize(left))
          error(0)
        end
        if GetToken(right) ~= "number" then
          print("expected number, got " .. Tokenize(right))
          error(0)
        end

        return tonumber(ConvertBases(left)) / tonumber(ConvertBases(right))
      elseif node["type"] == "equality" then
        -- Equality
        local left = Interpret(node["left"])
        local right = Interpret(node["right"])
        if GetToken(left) == "string" then
          left = string.sub(left, 2, #left - 1)
        end
        if GetToken(right) == "string" then
          right = string.sub(right, 2, #right - 1)
        end

        if GetToken(left) == "number" then
          left = tostring(left)
        end
        if GetToken(right) == "number" then
          right = tostring(right)
        end

        return tostring(left == right)
      elseif node["type"] == "inferior equal" then
        -- Inferior Equal
        local left = Interpret(node["left"])
        local right = Interpret(node["right"])
        if GetToken(left) ~= "number" then
          print("expected number, got " .. Tokenize(left))
          error(0)
        end
        if GetToken(right) ~= "number" then
          print("expected number, got " .. Tokenize(right))
          error(0)
        end

        return tostring(tonumber(ConvertBases(left)) <= tonumber(ConvertBases(right)))
      elseif node["type"] == "superior equal" then
        -- Superior Equal
        local left = Interpret(node["left"])
        local right = Interpret(node["right"])
        if GetToken(left) ~= "number" then
          print("expected number, got " .. Tokenize(left))
          error(0)
        end
        if GetToken(right) ~= "number" then
          print("expected number, got " .. Tokenize(right))
          error(0)
        end

        return tostring(tonumber(ConvertBases(left)) >= tonumber(ConvertBases(right)))
      elseif node["type"] == "inferiority" then
        -- Inferiority
        local left = Interpret(node["left"])
        local right = Interpret(node["right"])
        if GetToken(left) ~= "number" then
          print("expected number, got " .. Tokenize(left))
          error(0)
        end
        if GetToken(right) ~= "number" then
          print("expected number, got " .. Tokenize(right))
          error(0)
        end

        return tostring(tonumber(ConvertBases(left)) < tonumber(ConvertBases(right)))
      elseif node["type"] == "superiority" then
        -- Superiority
        local left = Interpret(node["left"])
        local right = Interpret(node["right"])
        if GetToken(left) ~= "number" then
          print("expected number, got " .. Tokenize(left))
          error(0)
        end
        if GetToken(right) ~= "number" then
          print("expected number, got " .. Tokenize(right))
          error(0)
        end

        return tostring(tonumber(ConvertBases(left)) > tonumber(ConvertBases(right)))
      elseif node["type"] == "or gate" then
        -- OR Gate
        local left = Interpret(node["left"])
        local right = Interpret(node["right"])
        if GetToken(left) ~= "bool" then
          print("expected bool, got " .. Tokenize(left))
          error(0)
        end
        if GetToken(right) ~= "bool" then
          print("expected bool, got " .. Tokenize(right))
          error(0)
        end

        if left == "true" or right == "true" then
          return "true"
        end
        return "false"
      elseif node["type"] == "and gate" then
        -- AND Gate
        local left = Interpret(node["left"])
        local right = Interpret(node["right"])
        if GetToken(left) ~= "bool" then
          print("expected bool, got " .. Tokenize(left))
          error(0)
        end
        if GetToken(right) ~= "bool" then
          print("expected bool, got " .. Tokenize(right))
          error(0)
        end

        if left == "true" and right == "true" then
          return "true"
        end
        return "false"
      elseif node["type"] == "xor gate" then
        -- XOR Gate
        local left = Interpret(node["left"])
        local right = Interpret(node["right"])
        if GetToken(left) ~= "bool" then
          print("expected bool, got " .. Tokenize(left))
          error(0)
        end
        if GetToken(right) ~= "bool" then
          print("expected bool, got " .. Tokenize(right))
          error(0)
        end

        if (left == "true" and right == "false") or (left == "false" and right == "true") then
          return "true"
        end
        return "false"
      elseif node["type"] == "not gate" then
        -- NOT Gate
        local right = Interpret(node["right"])
        if GetToken(right) ~= "bool" then
          print("expected bool, got " .. Tokenize(right))
          error(0)
        end

        if right == "true" then
          return "false"
        end
        return "true"
      elseif node["type"] == "modulo" then
        -- Modulo
        local left = Interpret(node["left"])
        local right = Interpret(node["right"])
        if GetToken(left) ~= "number" then
          print("expected number, got " .. Tokenize(left))
          error(0)
        end
        if GetToken(right) ~= "number" then
          print("expected number, got " .. Tokenize(right))
          error(0)
        end

        return tostring(ConvertBases(left) % ConvertBases(right))
      elseif node["type"] == "variable declaration" or node["type"] == "global declaration" then
        -- Variable Declaration
        if node["type"] == "variable declaration" then
          local value = Interpret(node["value"])
          if value == nil then
            Scopes_add(node["variable"], "null")
            return nil
          end

          if type(value) == "table" then
            if value["type"] == "require" then
              current_path[node["variable"]] = {
                ["arguments"] = {},
                ["class"] = value["value"]
              }

              instances[node["variable"]] = value

              return nil
            elseif value["class"] then
              current_path[node["variable"]] = {
                ["arguments"] = value["arguments"],
                ["class"] = value["class"]
              }

              instances[node["variable"]] = value

              return nil
            end

            Scopes_add(node["variable"], copy(value))

            return nil
          end

          Scopes_add(node["variable"], value)
        else
          local value = Interpret(node["value"])
          if value == nil then
            global_variables[node["variable"]] = "null"
            return nil
          end

          if type(value) == "table" then
            if value["class"] then
              current_path[node["variable"]] = {
                ["arguments"] = value["arguments"],
                ["class"] = value["class"]
              }

              instances[node["variable"]] = value
                
              return nil
            end

            global_variables[node["variable"]] = copy(value)
              
            return nil
          end
            
          global_variables[node["variable"]] = value
        end
      elseif node["type"] == "variable change" then
        -- Variable Change
        local increment = Interpret(node["value"])
        if GetToken(increment) ~= "number" then
          print("expected number, got " .. GetToken(Tokenize(increment)))
          error(0)
        end

        if global_variables[node["variable"]] then
          if GetToken(global_variables[node["variable"]]) ~= "number" then
            print("expected number, got " .. Tokenize(global_variables[node["variable"]]))
            error(0)
          end
          global_variables[node["variable"]] = ConvertBases(global_variables[node["variable"]]) +
              ConvertBases(Interpret(node["value"]))
        elseif scopes[node["variable"]] then
          if GetToken(scopes[node["variable"]]) ~= "number" then
            print("expected number, got " .. Tokenize(scopes[node["variable"]]))
            error(0)
          end
          scopes[node["variable"]] = ConvertBases(scopes[node["variable"]]) + ConvertBases(Interpret(node["value"]))
        else
          print("trying to change variable '" .. Tokenize(node["variable"]) .. "' never declared")
          error(0)
        end
      elseif node["type"] == "function declaration" then
        -- Function Declaration
        current_path[node["function"]] = {
          ["arguments"] = node["arguments"],
          ["body"] = node["body"]
        }
        if node["data types"] then
          current_path[node["function"]]["data types"] = node["data types"]
        end
      elseif node["type"] == "class declaration" then
        -- Class Declaration
        classes[node["class"]] = {
          ["arguments"] = node["arguments"],
          ["class"] = node["body"]
        }
      elseif node["type"] == "if statement" then
        -- If Statement
        if Interpret(node["condition"]) == "true" then
          Scopes_new()
          for i, v in pairs(node["body"]) do
            local interpreted = Interpret(node["body"][i])
            if interpreted then
              if interpreted["type"] == "keyword" then
                if interpreted["keyword"] == "return" then
                  return_value = interpreted
                end
              end
            end
          end
          Scopes_remove()

          return return_value
        elseif node["else body"] then
          Scopes_new()
          for i, v in pairs(node["else body"]) do
            local interpreted = Interpret(node["else body"][i])
            if interpreted then
              if interpreted["type"] == "keyword" then
                if interpreted["keyword"] == "return" then
                  return_value = interpreted
                end
              end
            end
          end
          Scopes_remove()

          return return_value
        end
      elseif node["type"] == "repeat amount loop" then
        -- Repeat Amount Loop
        local amount = Interpret(node["amount"])
        if GetToken(amount) ~= "number" then
          print("expected number, got " .. Tokenize(amount))
          error(0)
        end
        Scopes_new()
        if Round(ConvertBases(amount)) > 0 then
          for j = 1, Round(ConvertBases(amount)) do
            for i, v in pairs(node["body"]) do
              local interpreted = Interpret(node["body"][i])
              if interpreted then
                if interpreted["type"] == "keyword" then
                  if interpreted["keyword"] == "skip" then
                    break
                  elseif interpreted["keyword"] == "stop" then
                    goto stop
                  end
                  return_value = interpreted
                end
              end
            end
          end
          ::stop::
        end
        Scopes_remove()
      elseif node["type"] == "repeat until loop" then
        -- Repeat Until Loop
        Scopes_new()
        repeat
          for i, v in pairs(node["body"]) do
            local interpreted = Interpret(node["body"][i])
            if interpreted then
              if interpreted["type"] == "keyword" then
                if interpreted["keyword"] == "skip" then
                  break
                elseif interpreted["keyword"] == "stop" then
                  goto stop
                end
                return_value = interpreted
              end
            end
          end
        until Interpret(node["condition"]) == "true"
        ::stop::
        Scopes_remove()
      elseif node["type"] == "while loop" then
        -- While Loop
        if Interpret(node["condition"]) == "true" then
          Scopes_new()
          while Interpret(node["condition"]) == "true" do
            for i, v in pairs(node["body"]) do
              local interpreted = Interpret(node["body"][i])
              if interpreted then
                if interpreted["type"] == "keyword" then
                  if interpreted["keyword"] == "skip" then
                    break
                  elseif interpreted["keyword"] == "stop" then
                    goto stop
                  end
                  return_value = interpreted
                end
              end
            end
          end
          ::stop::
          Scopes_remove()
        end
      elseif node["type"] == "for loop" then
        -- For Loop
        Scopes_new()
        if node["value"] then
          local list = Interpret(node["list"])
          if type(list) ~= "table" then
            print("expected list, got " .. GetDataType(Tokenize(node["list"]), Tokenize(list)))
            error(0)
          end

          local ordered_index = {}
          local ordered_value = {}

          for i, v in pairs(list) do
            table.insert(ordered_index, i)
          end
          table.sort(ordered_index)

          for i, v in pairs(ordered_index) do
            table.insert(ordered_value, list[v])
          end

          for j, b in pairs(ordered_index) do
            Scopes_add(node["counter"]["value"], b)
            Scopes_add(node["value"]["value"], Interpret(ordered_value[j]))
            for i, v in pairs(node["body"]) do
              local interpreted = Interpret(node["body"][i])
              if type(interpreted) == "table" then
                if interpreted then
                  if interpreted["type"] == "keyword" then
                    if interpreted["keyword"] == "skip" then
                      break
                    elseif interpreted["keyword"] == "stop" then
                      goto stop
                    end
                    return_value = interpreted
                  end
                end
              end
            end
          end
        else
          for j = ConvertBases(Interpret(node["start"])), ConvertBases(Interpret(node["goal"])) do
            Scopes_add(node["counter"]["value"], j)
            for i, v in pairs(node["body"]) do
              local interpreted = Interpret(node["body"][i])
              if type(interpreted) == "table" then
                if interpreted then
                  if interpreted["type"] == "keyword" then
                    if interpreted["keyword"] == "skip" then
                      break
                    elseif interpreted["keyword"] == "stop" then
                      goto stop
                    end
                    return_value = interpreted
                  end
                end
              end
            end
          end
        end
        ::stop::
        Scopes_remove()
      elseif node["type"] == "number" or node["type"] == "string" or node["type"] == "bool" or node["type"] == "null" then
        -- Literal
        return node["value"]
      elseif node["type"] == "identifier" then
        -- Identifier

        if scopes[node["value"]] or global_variables[node["value"]] then
          -- Variable Call
          if node["path"] and not functions[scopes[node["value"]]] then
            print("'" .. Tokenize(node["value"]) .. "' is not a class")
            error(0)
          end

          return global_variables[node["value"]] or scopes[node["value"]]
        elseif functions[node["value"]] then
          -- Function Call

          if functions[node["value"]]["body"] then
            -- User Function
            if not node["arguments"] and #functions[node["value"]]["arguments"] ~= 0 then
              print("expected " .. #functions[node["value"]]["arguments"] .. " arguments, got 0")
              error(0)
            elseif node["arguments"] then
              if #functions[node["value"]]["arguments"] ~= #node["arguments"] then
                print("expected " .. #functions[node["value"]]["arguments"] .. " arguments, got " .. #node["arguments"])
                error(0)
              end
            end

            Scopes_new()
            for i, v in pairs(functions[node["value"]]["arguments"]) do
              local argument = Interpret(node["arguments"][i])

              if Find_in_array(v["data types"], GetDataType(node["arguments"][i], argument)) == 0 then
                if Find_in_array(v["data types"], "any") == 0 then
                  print("wrong data type: expected " ..
                    table.concat(v[i]["token"]["data types"], " or ") ..
                    ", got " .. GetDataType(node["arguments"][i], argument))
                  error(0)
                end
              end

              Scopes_add(v["token"], argument)
            end

            local non_interpreted_return
            local return_value
            for i, v in pairs(functions[node["value"]]["body"]) do
              local interpreted = Interpret(functions[node["value"]]["body"][i])
              if interpreted then
                if interpreted["type"] == "keyword" then
                  if interpreted["keyword"] == "return" then
                    non_interpreted_return = interpreted
                    return_value = Interpret(interpreted["value"])
                    break
                  end
                end
              end
            end
            Scopes_remove()

            if Find_in_array(functions[node["value"]]["data types"], GetDataType(non_interpreted_return, return_value)) == 0 then
              if Find_in_array(functions[node["value"]]["data types"], "any") == 0 then
                print("wrong data type: expected " ..
                  table.concat(functions[node["value"]]["data types"], " or ") ..
                  ", got " .. GetDataType(non_interpreted_return, return_value))
                error(0)
              end
            end

            return return_value
          elseif functions[node["value"]]["class"] then
            -- Class
            Scopes_new()
            for i, v in pairs(functions[node["value"]]["arguments"]) do
              Scopes_add(i, v)
            end

            for i, v in pairs(functions[node["value"]]["class"]) do
              Interpret(functions[node["value"]]["class"][i])
            end

            local return_value
            if node["path"] then
              return_value = Interpret(node["path"])
            end

            for i, v in pairs(functions[node["value"]]["arguments"]) do
              functions[node["value"]]["arguments"][i] = scopes[i]
            end
            Scopes_remove()

            return return_value
          else
            -- Built-in Function
            if node["path"] then
              if not Find_index_in_array(current_path, node["value"]) then
                print("path '" .. Tokenize(node["value"]) .. "' does not exist")
                error(0)
              end
              current_path = current_path[node["value"]]
              table.insert(last_path, node["value"])
              return Interpret(node["path"])
            end
          end
        else
          if current_path[node["value"]] then
            if not node["arguments"] and #current_path[node["value"]]["arguments"] ~= 0 then
              print("expected " .. #current_path[node["value"]]["arguments"] .. " arguments, got 0")
              error(0)
            elseif node["arguments"] then
              if #current_path[node["value"]]["arguments"] ~= #node["arguments"] then
                print("expected " ..
                  #current_path[node["value"]]["arguments"] .. " arguments, got " .. #node["arguments"])
                error(0)
              end
            end

            current_path = functions

            if EqualLists(last_path, { "debug" }) then
              -- DEBUG
              last_path = {}
              if node["value"] == "log" then
                -- Log Function
                local argument1 = Interpret(node["arguments"][1])
                if GetToken(argument1) == "string" then
                  print(string.sub(argument1, 2, #argument1 - 1))
                else
                  if argument1 == nil then
                    print("null")
                    return nil
                  else
                    print(tostring(argument1))
                  end
                end

                return nil
              elseif node["value"] == "warn" then
                -- Warn Function
                local argument1 = Interpret(node["arguments"][1])
                if GetToken(Interpret(node["arguments"][1])) == "string" then
                  print("WARN: " .. string.sub(argument1, 2, #argument1 - 1))
                else
                  if argument1 == nil then
                    print("WARN: null")
                    return nil
                  end
                  print("WARN: " .. tostring(argument1))
                end

                return nil
              elseif node["value"] == "error" then
                -- Error Function
                local argument1 = Interpret(node["arguments"][1])
                if GetToken(Interpret(node["arguments"][1])) == "string" then
                  print(string.sub(argument1, 2, #argument1 - 1))
                  error(0)
                else
                  if argument1 == nil then
                    print("null")
                    error(0)
                  end
                  print(tostring(argument1))
                  error(0)
                end

                return nil
              elseif node["value"] == "write" then
                -- Write Function
                local argument1 = Interpret(node["arguments"][1])
                if GetToken(argument1) == "string" then
                  io.write(string.sub(argument1, 2, #argument1 - 1))
                else
                  if argument1 == nil then
                    io.write("null")
                    return nil
                  else
                    io.write(tostring(argument1))
                  end
                end

                return nil
              end
            elseif EqualLists(last_path, { "math" }) then
              -- MATH
              last_path = {}
              if node["value"] == "random" then
                -- Random Function
                local minimum = Interpret(node["arguments"][1])
                local maximum = Interpret(node["arguments"][2])
                if GetToken(minimum) ~= "number" then
                  print("argument 1 isn't a number: " .. Tokenize(maximum))
                  error(0)
                end
                if GetToken(maximum) ~= "number" then
                  print("argument 2 isn't a number: " .. Tokenize(maximum))
                  error(0)
                end

                return math.random(tonumber(ConvertBases(minimum)), tonumber(ConvertBases(maximum)))
              elseif node["value"] == "clamp" then
                -- Clamp Function
                local minimum = Interpret(node["arguments"][2])
                local maximum = Interpret(node["arguments"][3])

                local argument1 = Interpret(node["arguments"][1])
                if GetToken(minimum) ~= "number" then
                  print("argument 2 isn't a number: " .. Tokenize(minimum))
                  error(0)
                end
                if GetToken(maximum) ~= "number" then
                  print("argument 3 isn't a number: " .. Tokenize(maximum))
                  error(0)
                end

                if GetToken(argument1) ~= "number" then
                  print("argument 1 isn't a number: " .. Tokenize(argument1))
                  error(0)
                end

                return Clamp(tonumber(ConvertBases(argument1)), tonumber(ConvertBases(minimum)),
                  tonumber(ConvertBases(maximum)))
              elseif node["value"] == "min" then
                -- Minimum Function
                local argument1 = Interpret(node["arguments"][1])
                local argument2 = Interpret(node["arguments"][2])
                if GetToken(argument1) ~= "number" then
                  print("argument 1 isn't a number: " .. Tokenize(argument1))
                  error(0)
                end
                if GetToken(argument2) ~= "number" then
                  print("argument 2 isn't a number: " .. Tokenize(argument2))
                  error(0)
                end

                if ConvertBases(argument1) < ConvertBases(argument2) then
                  return ConvertBases(argument2)
                end
                return ConvertBases(argument1)
              elseif node["value"] == "max" then
                -- Maximum Function
                local argument1 = Interpret(node["arguments"][1])
                local argument2 = Interpret(node["arguments"][2])
                if GetToken(argument1) ~= "number" then
                  print("argument 1 isn't a number: " .. Tokenize(argument1))
                  error(0)
                end
                if GetToken(argument2) ~= "number" then
                  print("argument 2 isn't a number: " .. Tokenize(argument2))
                  error(0)
                end

                if ConvertBases(argument1) > ConvertBases(argument2) then
                  return ConvertBases(argument2)
                end
                return ConvertBases(argument1)
              elseif node["value"] == "exp" then
                -- Exponent Function
                local base = Interpret(node["arguments"][1])
                local exponent = Interpret(node["arguments"][2])
                if GetToken(base) ~= "number" then
                  print("argument 1 isn't a number: " .. Tokenize(base))
                  error(0)
                end
                if GetToken(exponent) ~= "number" then
                  print("argument 2 isn't a number: " .. Tokenize(exponent))
                  error(0)
                end

                return ConvertBases(base) ^ ConvertBases(exponent)
              elseif node["value"] == "abs" then
                -- Absolute Function
                local argument1 = Interpret(node["arguments"][1])
                if GetToken(argument1) ~= "number" then
                  print("argument 1 isn't a number: " .. Tokenize(argument1))
                  error(0)
                end

                return math.abs(tonumber(ConvertBases(argument1)))
              elseif node["value"] == "floor" then
                -- Floor Function
                local argument1 = Interpret(node["arguments"][1])
                if GetToken(argument1) ~= "number" then
                  print("argument 1 isn't a number: " .. Tokenize(argument1))
                  error(0)
                end

                return math.floor(tonumber(ConvertBases(argument1)))
              elseif node["value"] == "ceiling" then
                -- Ceiling Function
                local argument1 = Interpret(node["arguments"][1])
                if GetToken(argument1) ~= "number" then
                  print("argument 1 isn't a number: " .. Tokenize(argument1))
                  error(0)
                end

                return math.ceil(tonumber(ConvertBases(argument1)))
              elseif node["value"] == "round" then
                -- Round Function
                local argument1 = Interpret(node["arguments"][1])
                local argument2 = Interpret(node["arguments"][2])
                if GetToken(argument1) ~= "number" then
                  print("argument 1 isn't a number: " .. Tokenize(argument1))
                  error(0)
                end
                if GetToken(argument2) ~= "number" then
                  print("argument 2 isn't a number: " .. Tokenize(argument2))
                  error(0)
                end

                return Round(tonumber(ConvertBases(argument1)) * math.pow(10, tonumber(ConvertBases(argument2)))) /
                    math.pow(10, tonumber(ConvertBases(argument2)))
              elseif node["value"] == "sqrt" then
                -- Square Root Function
                local argument1 = Interpret(node["arguments"][1])
                if GetToken(argument1) ~= "number" then
                  print("argument 1 isn't a number: " .. Tokenize(argument1))
                  error(0)
                end

                return math.sqrt(tonumber(ConvertBases(argument1)))
              elseif node["value"] == "sin" then
                -- Sine Function
                local argument1 = Interpret(node["arguments"][1])
                if GetToken(argument1) ~= "number" then
                  print("argument 1 isn't a number: " .. Tokenize(argument1))
                  error(0)
                end

                return math.sin(math.rad(tonumber(ConvertBases(argument1))))
              elseif node["value"] == "cos" then
                -- Cosine Function
                local argument1 = Interpret(node["arguments"][1])
                if GetToken(argument1) ~= "number" then
                  print("argument 1 isn't a number: " .. Tokenize(argument1))
                  error(0)
                end

                return math.cos(math.rad(tonumber(ConvertBases(argument1))))
              elseif node["value"] == "tan" then
                -- Tangent Function
                local argument1 = Interpret(node["arguments"][1])
                if GetToken(argument1) ~= "number" then
                  print("argument 1 isn't a number: " .. Tokenize(argument1))
                  error(0)
                end

                return math.tan(math.rad(tonumber(ConvertBases(argument1))))
              elseif node["value"] == "asin" then
                -- Arc Sine Function
                local argument1 = Interpret(node["arguments"][1])
                if GetToken(argument1) ~= "number" then
                  print("argument 1 isn't a number: " .. Tokenize(argument1))
                  error(0)
                end

                return math.asin(math.rad(tonumber(ConvertBases(argument1))))
              elseif node["value"] == "acos" then
                -- Arc Cosine Function
                local argument1 = Interpret(node["arguments"][1])
                if GetToken(argument1) ~= "number" then
                  print("argument 1 isn't a number: " .. Tokenize(argument1))
                  error(0)
                end

                return math.acos(math.rad(tonumber(ConvertBases(argument1))))
              elseif node["value"] == "atan" then
                -- Arc Tangent Function
                local argument1 = Interpret(node["arguments"][1])
                if GetToken(argument1) ~= "number" then
                  print("argument 1 isn't a number: " .. Tokenize(argument1))
                  error(0)
                end

                return math.atan(math.rad(tonumber(ConvertBases(argument1))))
              elseif node["value"] == "sinh" then
                -- Hyperbolic Sine Function
                local argument1 = Interpret(node["arguments"][1])
                if GetToken(argument1) ~= "number" then
                  print("argument 1 isn't a number: " .. Tokenize(argument1))
                  error(0)
                end

                return math.sinh(math.rad(tonumber(ConvertBases(argument1))))
              elseif node["value"] == "cosh" then
                -- Hyperbolic Cosine Function
                local argument1 = Interpret(node["arguments"][1])
                if GetToken(argument1) ~= "number" then
                  print("argument 1 isn't a number: " .. Tokenize(argument1))
                  error(0)
                end

                return math.cosh(math.rad(tonumber(ConvertBases(argument1))))
              elseif node["value"] == "tanh" then
                -- Hyperbolic Tangent Function
                local argument1 = Interpret(node["arguments"][1])
                if GetToken(argument1) ~= "number" then
                  print("argument 1 isn't a number: " .. Tokenize(argument1))
                  error(0)
                end

                return math.tanh(math.rad(tonumber(ConvertBases(argument1))))
              elseif node["value"] == "ln" then
                -- Natural Logarithm Function
                local argument1 = Interpret(node["arguments"][1])
                if GetToken(argument1) ~= "number" then
                  print("argument 1 isn't a number: " .. Tokenize(argument1))
                  error(0)
                end

                return math.log(tonumber(ConvertBases(argument1)))
              elseif node["value"] == "log" then
                -- Logarithm Function
                local argument1 = Interpret(node["arguments"][1])
                local argument2 = Interpret(node["arguments"][2])
                if GetToken(argument1) ~= "number" then
                  print("argument 1 isn't a number: " .. Tokenize(argument1))
                  error(0)
                end
                if GetToken(argument2) ~= "number" then
                  print("argument 2 isn't a number: " .. Tokenize(argument2))
                  error(0)
                end

                return math.log(tonumber(ConvertBases(argument1)), tonumber(ConvertBases(argument2)))
              elseif node["value"] == "pi" then
                -- Pi Function
                return math.pi
              elseif node["value"] == "euler" then
                -- Euler Function
                return math.exp(1)
              elseif node["value"] == "rad" then
                -- Radians Function
                local argument1 = Interpret(node["arguments"][1])
                if GetToken(argument1) ~= "number" then
                  print("argument 1 isn't a number: " .. (argument1))
                  error(0)
                end

                return math.rad(tonumber(ConvertBases(argument1)))
              elseif node["value"] == "deg" then
                -- Degrees Function
                local argument1 = Interpret(node["arguments"][1])
                if GetToken(argument1) ~= "number" then
                  print("argument 1 isn't a number: " .. Tokenize(argument1))
                  error(0)
                end

                return math.deg(tonumber(ConvertBases(argument1)))
              elseif node["value"] == "base" then
                -- Base Function
                local argument1 = Interpret(node["arguments"][1])
                local argument2 = Interpret(node["arguments"][2])
                if GetToken(argument1) ~= "number" then
                  print("argument 1 isn't a number: " .. Tokenize(argument1))
                  error(0)
                end
                if GetToken(argument2) ~= "number" then
                  print("argument 2 isn't a number: " .. Tokenize(argument2))
                  error(0)
                end

                if ConvertBases(argument2) > 10 then
                  print("argument 2 cannot exceed 10: " .. Tokenize(argument2))
                  error(0)
                elseif ConvertBases(argument2) < 2 then
                  print("argument 2 cannot be below 2: " .. Tokenize(argument2))
                  error(0)
                end

                argument2 = Round(tonumber(argument2), 0)

                local isHex = false
                local isBin = false
                if string.sub(tostring(argument1), 1, 2) == "0x" then
                  argument1 = string.sub(tostring(argument1), 3, #tostring(argument1))
                  isHex = true
                elseif string.sub(tostring(argument1), 1, 2) == "0b" then
                  argument1 = string.sub(tostring(argument1), 3, #tostring(argument1))
                  isBin = true
                else
                  argument1 = ConvertBases(argument1)
                end

                local baseResult = 0
                local target = argument1
                if isHex then
                  for i = 1, #tostring(argument1) do
                    local char = string.sub(tostring(argument1), i, i)

                    baseResult = baseResult + hex_table[char] * math.pow(16, #tostring(argument1) - i)
                  end

                  target = baseResult
                elseif isBin then
                  for i = 1, #tostring(argument1) do
                    local char = string.sub(tostring(argument1), i, i)

                    baseResult = baseResult + bin_table[char] * math.pow(2, #tostring(argument1) - i)
                  end

                  target = baseResult
                end

                local result = ""
                while target > 0 do
                  result = "" .. (target % tonumber(argument2)) .. result
                  target = math.floor(target / tonumber(argument2))
                end

                return tostring(result)
              elseif node["value"] == "inf" then
                -- Infinity Function
                return math.huge
              end
            elseif EqualLists(last_path, { "string" }) then
              -- STRING
              last_path = {}
              if node["value"] == "join" then
                -- Join Function
                local argument1 = Interpret(node["arguments"][1])
                local argument2 = Interpret(node["arguments"][2])

                local string_1 = argument1
                local string_2 = argument2

                if GetToken(argument1) == "string" then
                  string_1 = string.sub(argument1, 2, #argument1 - 1)
                end
                if GetToken(argument2) == "string" then
                  string_2 = string.sub(argument2, 2, #argument2 - 1)
                end

                if GetToken(argument1) == "string" or GetToken(argument2) == "string" then
                  return '"' .. string_1 .. string_2 .. '"'
                end

                return string_1 .. string_2
              elseif node["value"] == "length" then
                -- Length Function
                local argument1 = Interpret(node["arguments"][1])
                if type(argument1) == "table" then
                  print("argument 1 isn't a string, number or bool: " .. Tokenize(argument1))
                  error(0)
                end
                if GetToken(argument1) == "string" then
                  argument1 = string.sub(argument1, 2, #argument1 - 1)
                end

                return tostring(#tostring(argument1))
              elseif node["value"] == "letter" then
                -- Letter Function
                local argument1 = Interpret(node["arguments"][1])
                local argument2 = Interpret(node["arguments"][2])
                if GetToken(argument1) == "string" then
                  argument1 = string.sub(argument1, 2, #argument1 - 1)
                end
                if GetToken(argument2) ~= "number" then
                  print("argument 2 isn't a number: " .. Tokenize(argument))
                  error(0)
                end

                return string.sub(tostring(argument1), tonumber(ConvertBases(argument2)),
                  tonumber(ConvertBases(argument2)))
              elseif node["value"] == "contains" then
                -- Contains Function
                local argument1 = Interpret(node["arguments"][1])
                if type(argument1) == "table" then
                  print("argument 1 isn't a string, number or bool: " .. Tokenize(argument1))
                  error(0)
                end
                if GetToken(argument1) == "string" then
                  argument1 = string.sub(argument1, 2, #argument1 - 1)
                end

                local argument2 = Interpret(node["arguments"][2])
                if GetToken(argument2) == "string" then
                  argument2 = string.sub(argument2, 2, #argument2 - 1)
                end

                if string.find(argument1, argument2) then
                  return "true"
                end
                return "false"
              elseif node["value"] == "upper" then
                -- Upper Function
                return string.upper(tostring(Interpret(node["arguments"][1])))
              elseif node["value"] == "lower" then
                -- Lower Function
                return string.lower(tostring(Interpret(node["arguments"][1])))
              elseif node["value"] == "replace" then
                -- Replace Function
                local argument1 = Interpret(node["arguments"][1])
                if GetToken(argument1) == "string" then
                  argument1 = string.sub(argument1, 2, #argument1 - 1)
                end

                local argument2 = Interpret(node["arguments"][2])
                if GetToken(argument2) == "string" then
                  argument2 = string.sub(argument2, 2, #argument2 - 1)
                end

                local argument3 = Interpret(node["arguments"][3])
                if GetToken(argument3) == "string" then
                  argument3 = string.sub(argument3, 2, #argument3 - 1)
                end

                local argument4 = Interpret(node["arguments"][4])
                if GetToken(argument4) ~= "number" then
                  print("argument 4 isn't a number: " .. Tokenize(argument))
                  error(0)
                end

                return string.gsub(argument1, argument2, argument3, tonumber(ConvertBases(argument4)))
              elseif node["value"] == "split" then
                -- Split Function
                local argument1 = Interpret(node["arguments"][1])
                if GetToken(argument1) == "string" then
                  argument1 = string.sub(argument1, 2, #argument1 - 1)
                end

                local argument2 = Interpret(node["arguments"][2])
                if GetToken(argument2) == "string" then
                  argument2 = string.sub(argument2, 2, #argument2 - 1)
                end

                local new_string = {}
                local word = ""
                for i = 1, #argument1 do
                  local char = string.sub(argument1, i, i)
                  if char == argument2 then
                    table.insert(new_string, { ["type"] = "string", ["value"] = word })
                    word = ""
                  else
                    word = word .. char
                  end
                end
                if word ~= "" then
                  table.insert(new_string, { ["type"] = "string", ["value"] = word })
                end

                return new_string
              elseif node["value"] == "find" then
                -- Find Function
                local argument1 = Interpret(node["arguments"][1])
                if type(argument1) == "table" then
                  print("argument 1 isn't a string, number or bool: " .. Tokenize(argument))
                  error(0)
                end
                if GetToken(argument1) == "string" then
                  argument1 = string.sub(argument1, 2, #argument1 - 1)
                end

                local argument2 = Interpret(node["arguments"][2])
                if GetToken(argument2) == "string" then
                  argument2 = string.sub(argument2, 2, #argument2 - 1)
                end

                if string.find(argument1, argument2) then
                  local startpos, endpos = string.find(argument1, argument2)

                  return tostring(startpos)
                end
                return "null"
              end
            elseif EqualLists(last_path, { "control" }) then
              -- CONTROL
              last_path = {}
              if node["value"] == "type" then
                -- Type Function
                return GetDataType(node["arguments"][1], Interpret(node["arguments"][1]))
              elseif node["value"] == "wait" then
                -- Wait Function
                local argument1 = Interpret(node["arguments"][1])
                if GetToken(argument1) ~= "number" then
                  print("argument 1 isn't a number: " .. Tokenize(argument))
                  error(0)
                end

                Wait(tonumber(ConvertBases(argument1)))

                return nil
              elseif node["value"] == "tonumber" then
                -- To Number Function
                local argument1 = Interpret(node["arguments"][1])
                if GetToken(argument1) == "string" then
                  argument1 = string.sub(argument1, 2, #argument1 - 1)
                end

                return tonumber(argument1)
              elseif node["value"] == "tostring" then
                -- To String Function
                local argument1 = Interpret(node["arguments"][1])
                if GetToken(argument1) ~= "string" then
                  argument1 = '"' .. argument1 .. '"'
                end

                return argument1
              end
            elseif EqualLists(last_path, { "list" }) then
              -- LIST
              last_path = {}
              if node["value"] == "item" then
                -- Item Functcion
                local argument1 = Interpret(node["arguments"][1])
                if type(argument1) ~= "table" then
                  print("argument 1 isn't a list: " .. Tokenize(argument1))
                  error(0)
                end

                local argument2 = Interpret(node["arguments"][2])
                if GetToken(argument2) == "number" then
                  return Interpret(argument1[tonumber(argument2)])
                end

                return Interpret(argument1[argument2])
              elseif node["value"] == "add" then
                -- Add Function
                local argument1 = Interpret(node["arguments"][1])
                if type(argument1) ~= "table" then
                  print("argument 1 isn't a list: " .. Tokenize(argument1))
                  error(0)
                end

                table.insert(argument1, Interpret(node["arguments"][2]))

                return nil
              elseif node["value"] == "insert" then
                -- Insert Function
                local argument1 = Interpret(node["arguments"][1])
                local argument3 = Interpret(node["arguments"][3])
                if type(argument1) ~= "table" then
                  print("argument 1 isn't a list: " .. Tokenize(argument))
                  error(0)
                end

                if GetToken(argument3) == "number" then
                  argument1[tonumber(argument3)] = Interpret(node["arguments"][2])

                  return nil
                end
                argument1[argument3] = Interpret(node["arguments"][2])

                return nil
              elseif node["value"] == "length" then
                -- Length Function
                local argument1 = Interpret(node["arguments"][1])
                if type(argument1) ~= "table" then
                  print("argument 1 isn't a list: " .. Tokenize(argument1))
                  error(0)
                end

                return tostring(#argument1)
              elseif node["value"] == "position" then
                -- Position Function
                local argument1 = Interpret(node["arguments"][1])
                if type(argument1) ~= "table" then
                  print("argument 1 isn't a list: " .. Tokenize(argument1))
                  error(0)
                end

                return Find_in_array(argument1, Interpret(node["arguments"][2]))
              elseif node["value"] == "delete" then
                -- Delete Function
                local argument1 = Interpret(node["arguments"][1])
                local argument2 = Interpret(node["arguments"][2])
                if type(argument1) ~= "table" then
                  print("argument 1 isn't a list: " .. Tokenize(argument1))
                  error(0)
                end

                if GetToken(argument2) == "number" then
                  argument1[tonumber(argument2)] = nil

                  return nil
                end
                argument1[argument2] = nil

                return nil
              elseif node["value"] == "replace" then
                -- Replace Function
                local argument1 = Interpret(node["arguments"][1])
                local argument2 = Interpret(node["arguments"][2])
                if type(argument1) ~= "table" then
                  print("argument 1 isn't a list: " .. Tokenize(argument))
                  error(0)
                end

                if argument1[argument2] == nil then
                  print("argument 2 is out of bounds: " .. Tokenize(argument2))
                  error(0)
                end

                if GetToken(argument2) == "number" then
                  argument1[tonumber(argument2)] = Interpret(node["arguments"][3])

                  return nil
                end
                argument1[argument2] = Interpret(node["arguments"][3])

                return nil
              elseif node["value"] == "contains" then
                -- Contains Function
                local argument1 = Interpret(node["arguments"][1])
                if type(argument1) ~= "table" then
                  print("argument 1 isn't a list: " .. Tokenize(argument1))
                  error(0)
                end

                for i, v in pairs(argument1) do
                  if Interpret(v) == Interpret(node["arguments"][2]) then
                    return "true"
                  end
                end
                return "false"
              elseif node["value"] == "clear" then
                -- Clear Function
                local argument1 = Interpret(node["arguments"][1])
                if type(argument1) ~= "table" then
                  print("argument 1 isn't a list: " .. Tokenize(argument1))
                  error(0)
                end

                for i, v in pairs(argument1) do
                  argument1[i] = nil
                end

                return nil
              elseif node["value"] == "concatenate" then
                -- Concatenate Function
                local argument1 = Interpret(node["arguments"][1])
                local argument2 = Interpret(node["arguments"][2])
                if type(argument1) ~= "table" then
                  print("argument 1 isn't a list: " .. Tokenize(argument1))
                  error(0)
                end
                if GetToken(argument2) ~= "string" then
                  print("argument 2 isn't a string: " .. Tokenize(argument2))
                  error(0)
                end

                local new_list = argument1
                for i, v in pairs(new_list) do
                  if GetToken(v) == "string" then
                    new_list[i] = string.sub(v, 2, #v - 1)
                  end
                end

                argument2 = string.sub(argument2, 2, #argument2 - 1)
                return '"' .. table.concat(new_list, argument2) .. '"'
              end
            elseif EqualLists(last_path, { "instance" }) then
              -- INSTANCE
              last_path = {}
              if node["value"] == "new" then
                -- New Function
                local argument1 = node["arguments"][1]
                if not classes[argument1["value"]] then
                  print("argument 1 isn't a class: " .. Tokenize(argument1))
                  error(0)
                end

                local class = classes[argument1["value"]]

                if not argument1["arguments"] and #class["arguments"] ~= 0 then
                  print("expected " .. #class["arguments"] .. " arguments, got 0")
                  error(0)
                elseif argument1["arguments"] then
                  if #class["arguments"] ~= #argument1["arguments"] then
                    print("expected " .. #class["arguments"] .. " arguments, got " .. #argument1["arguments"])
                    error(0)
                  end
                end

                local instance = {}
                instance["class"] = class["class"]
                instance["arguments"] = {}

                for i, v in pairs(class["arguments"]) do
                  instance["arguments"][v] = Interpret(argument1["arguments"][i])
                end

                return instance
              elseif node["value"] == "destroy" then
                -- Destroy Function
                local argument1 = node["arguments"][1]

                if not functions[argument1["value"]] then
                  print("argument 1 instance doesn't exist: " .. Tokenize(argument1))
                  error(0)
                end

                functions[argument1["value"]] = nil
                

                return nil
              end
            end
          end

          if classes[node["value"]] then
            -- Class Call
            return node["value"]
          end
          print("'" .. Tokenize(node["value"]) .. "' was never declared as a variable or a function")
          error(0)
        end
      elseif node["type"] == "list" then
        -- List
        local list = {}
        for i, v in pairs(node["value"]) do
          list[i] = Interpret(v)
        end

        return list
      elseif node["type"] == "keyword" then
        -- Keyword
        if node["keyword"] == "require" then
          local value = Interpret(node["value"])
          if GetToken(value) ~= "string" then
            print("expected string, got " .. GetDataType(Tokenize(value)))
            error(0)
          end
          value = string.sub(value, 2, #value - 1)
          local file = GetFile(value)
          if file == nil then
            print("file" .. node["value"] .. " does not exist")
            error(0)
          end
          if value == FILE then
            print("file cannot be the same as the original file")
            error(0)
          end

          if string.sub(value, #value - 3, #value) ~= ".sfw" then
            return file
          end
          local req_code_chunks = {}

          local req_chunk = ""
          local req_open_string = ""

          local req_string_index = 0
          local req_skip_index = 0
          for i = 1, #file do
            if req_skip_index == i then
              goto continue
            end

            local req_char = string.sub(file, i, i)

            if req_char == '"' and req_open_string == "" then
              if req_chunk ~= "" then
                table.insert(req_code_chunks, req_chunk)
              end
              req_chunk = ""

              req_string_index = i
              req_open_string = '"'
            elseif req_char == "'" and req_open_string == "" then
              if req_chunk ~= "" then
                table.insert(req_code_chunks, req_chunk)
              end
              req_chunk = ""

              req_string_index = i
              req_open_string = "'"
            end

            if req_char == " " or not string.find(allowed_chars, RemoveMagic(req_char)) then
              if req_open_string ~= "" then
                req_chunk = req_chunk .. req_char
              else
                if not (req_char == "-" and tonumber(string.sub(file, i + 1, i + 1)) and not tonumber(string.sub(file, i - 1, i - 1))) then
                  if req_chunk ~= "" then
                    table.insert(req_code_chunks, req_chunk)
                  end
                  if req_char ~= " " then
                    table.insert(req_code_chunks, req_char)
                  end
                  req_chunk = ""
                else
                  if req_chunk ~= "" then
                    table.insert(req_code_chunks, req_chunk)
                  end
                  req_chunk = "-"
                end
              end
            else
              if string.find(allowed_chars, RemoveMagic(req_char)) == 1 then
                if req_chunk ~= "" then
                  table.insert(req_code_chunks, req_chunk)
                end
                if req_char ~= " " then
                  table.insert(req_code_chunks, req_char)
                end
                req_chunk = ""

                goto continue
              end
              if req_open_string ~= "" then
                req_chunk = req_chunk .. req_char
              else
                if tonumber(req_char) and not tonumber(string.sub(file, i + 1, i + 1)) then
                  req_chunk = req_chunk .. req_char
                  if string.sub(file, i + 1, i + 1) == "." and tonumber(string.sub(file, i + 2, i + 2)) then
                    req_chunk = req_chunk .. string.sub(file, i + 1, i + 1)
                    req_skip_index = i + 1
                  else
                    if tostring(req_chunk) == "0" then
                      if string.sub(file, i + 1, i + 1) ~= "x" and string.sub(file, i + 1, i + 1) ~= "b" then
                        table.insert(req_code_chunks, req_chunk)
                        req_chunk = ""
                      end
                    else
                      req_chunk = string.sub(tostring(req_chunk), 1, #tostring(req_chunk) - 1)
                      if (not CheckBase(chunk, "x", hex_chars)) and (not CheckBase(chunk, "b", bin_chars)) then
                        table.insert(req_code_chunks, req_chunk .. req_char)
                        req_chunk = ""
                      else
                        if CheckBase(chunk, "b", bin_chars) then
                          if not string.find(bin_chars, req_char) then
                            table.insert(req_code_chunks, chunk)
                            req_chunk = req_char
                          else
                            if string.find(bin_chars, req_char) == 1 then
                              table.insert(req_code_chunks, req_chunk)
                              req_chunk = req_char
                            else
                              req_chunk = req_chunk .. req_char
                            end
                          end
                        else
                          req_chunk = req_chunk .. req_char
                        end
                      end
                    end
                  end
                else
                  if string.sub(tostring(req_chunk), 1, 1) == "0" and string.sub(tostring(req_chunk), 2, 2) == "x" then
                    if IsBase(req_char, hex_chars) then
                      req_chunk = req_chunk .. req_char
                    else
                      table.insert(req_code_chunks, req_chunk)
                      req_chunk = req_char
                    end
                  elseif string.sub(tostring(req_chunk), 1, 1) == "0" and string.sub(tostring(req_chunk), 2, 2) == "b" then
                    if IsBase(req_char, bin_chars) then
                      req_chunk = req_chunk .. req_char
                    else
                      table.insert(req_code_chunks, req_chunk)
                      req_chunk = req_char
                    end
                  else
                    req_chunk = req_chunk .. req_char
                  end
                end
              end
            end

            if req_char == '"' and req_open_string == '"' and req_string_index ~= i then
              if req_chunk ~= "" then
                table.insert(req_code_chunks, req_chunk)
              end
              req_chunk = ""

              req_open_string = ""
            elseif req_char == "'" and req_open_string == "'" and req_string_index ~= i then
              if req_chunk ~= "" then
                table.insert(req_code_chunks, req_chunk)
              end
              req_chunk = ""

              req_open_string = ""
            end

            ::continue::
          end
          if req_chunk ~= "" then
            table.insert(req_code_chunks, req_chunk)
          end

          local req_chunk_index = 0
          while not (req_chunk_index > #req_code_chunks) do
            req_chunk_index = req_chunk_index + 1

            if req_chunk_index > #req_code_chunks then
              break
            end

            if GetToken(req_code_chunks[req_chunk_index]) == "number" and string.sub(req_code_chunks[req_chunk_index], 1, 2) ~= "0x" and string.sub(req_code_chunks[req_chunk_index], 1, 2) ~= "0b" then
              req_code_chunks[req_chunk_index] = tonumber(req_code_chunks[req_chunk_index])
            end
            if GetToken(req_code_chunks[req_chunk_index]) == "whitespace" then
              table.remove(req_code_chunks, req_chunk_index)
              req_chunk_index = req_chunk_index - 1
            end
          end

          return {["type"] = "require", ["value"] = Parse(req_code_chunks, {}, true)}
        end
        return node
      end

      return return_value
    end

    local globalAST = Parse(code_chunks, {}, true)

    for i, v in pairs(globalAST) do
      Interpret(v)
    end
  end)
end

function GetFile(filename)
  local file = io.input(filename)

  if file then
    return file:read("a")
  else
    return nil
  end
end

RunCode(GetFile(FILE))