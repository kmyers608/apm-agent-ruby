# Licensed to Elasticsearch B.V. under one or more contributor
# license agreements. See the NOTICE file distributed with
# this work for additional information regarding copyright
# ownership. Elasticsearch B.V. licenses this file to you under
# the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

# frozen_string_literal: true

require 'elastic_apm/sql'

module ElasticAPM
  module Normalizers
    module ActiveRecord
      # @api private
      class SqlNormalizer < Normalizer
        register 'sql.active_record'

        COMPONENTS_REGEX_MAP = {
          single_quotes: /'(?:[^']|'')*?(?:\\'.*|'(?!'))/,
          double_quotes: /"(?:[^"]|"")*?(?:\\".*|"(?!"))/,
          numeric_literals: /-?\b(?:[0-9]+\.)?[0-9]+([eE][+-]?[0-9]+)?\b/,
          boolean_literals: /\b(?:true|false|null)\b/i,
          hexadecimal_literals: /0x[0-9a-fA-F]+/,
          comments: /(?:#|--).*?(?=\r|\n|$)/i,
          multi_line_comments: %r{\/\*(?:[^\/]|\/[^*])*?(?:\*\/|\/\*.*)}
        }.freeze

        MYSQL_COMPONENTS = %i[
          single_quotes
          double_quotes
          numeric_literals
          boolean_literals
          hexadecimal_literals
          comments
          multi_line_comments
        ].freeze

        TYPE = 'db'
        ACTION = 'sql'
        SKIP_NAMES = %w[SCHEMA CACHE].freeze
        UNKNOWN = 'unknown'

      def initialize(*args)
        super

        @summarizer = Sql.summarizer

        @adapters = {}
      end

        def obfuscate_sql(sql)
          #return sql unless ENV['ELASTIC_APM_SQL_OBFUSCATION']

          if sql.size > 2000
            'SQL query too large to remove sensitive data ...'
          else
            obfuscated = sql.gsub(generated_mysql_regex, '?')
            obfuscated = 'Failed to obfuscate SQL query - quote characters remained after obfuscation' if detect_unmatched_pairs(obfuscated)
            obfuscated
          end
        end

        def generated_mysql_regex
          @generated_mysql_regex ||= Regexp.union(MYSQL_COMPONENTS.map { |component| COMPONENTS_REGEX_MAP[component] })
        end

        def detect_unmatched_pairs(obfuscated)
          # We use this to check whether the query contains any quote characters
          # after obfuscation. If so, that's a good indication that the original
          # query was malformed, and so our obfuscation can't reliably find
          # literals. In such a case, we'll replace the entire query with a
          # placeholder.
          %r{'|"|\/\*|\*\/}.match(obfuscated)
        end

        def normalize(_transaction, _name, payload)
          return :skip if SKIP_NAMES.include?(payload[:name])

          name = summarize(payload[:sql]) || payload[:name]
          subtype = subtype_for(payload)

          context =
            Span::Context.new(
              db: { statement: obfuscate_sql(payload[:sql]), type: 'sql' },
              destination: { name: subtype, resource: subtype, type: TYPE }
            )

          [name, TYPE, subtype, ACTION, context]
        end

        private

        def subtype_for(payload)
          if payload[:connection]
            return cached_adapter_name(payload[:connection].adapter_name)
          end

          if can_attempt_connection_id_lookup?(payload)
            begin
              loaded_object = ObjectSpace._id2ref(payload[:connection_id])
              if loaded_object.respond_to?(:adapter_name)
                return cached_adapter_name(loaded_object.adapter_name)
              end
            rescue RangeError # if connection object has somehow been garbage collected
            end
          end

          cached_adapter_name(::ActiveRecord::Base.connection_config[:adapter])
        end

        def summarize(sql)
          @summarizer.summarize(sql)
        end

        def cached_adapter_name(adapter_name)
          return UNKNOWN if adapter_name.nil? || adapter_name.empty?

          @adapters[adapter_name] ||
            (@adapters[adapter_name] = adapter_name.downcase)
        rescue StandardError
          nil
        end

        def can_attempt_connection_id_lookup?(payload)
          RUBY_ENGINE == "ruby" &&
            payload[:connection_id] &&
            ObjectSpace.respond_to?(:_id2ref)
        end
      end
    end
  end
end
