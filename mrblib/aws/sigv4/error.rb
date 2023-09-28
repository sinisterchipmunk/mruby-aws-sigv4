module AWS
  module SigV4
    class Error < RuntimeError
      # The SigV4 library function received an invalid input parameter.
      #
      # Functions that may return this value:
      # - #SigV4_GenerateHTTPAuthorization
      # - #SigV4_AwsIotDateToIso8601
      class InvalidParameter < Error; end

      # The application buffer was not large enough for the specified hash
      # function.
      #
      # Functions that may return this value:
      # - #SigV4_GenerateHTTPAuthorization
      class InsufficientMemory < Error; end

      # An error occurred while formatting the provided date header.
      #
      # Functions that may return this value:
      # - #SigV4_AwsIotDateToIso8601
      class ISOFormattingError < Error; end

      # The maximum number of header parameters was exceeded while parsing
      # the http header string passed to the library.
      # The maximum number of supported HTTP headers can be configured
      # with the SIGV4_MAX_HTTP_HEADER_COUNT macro in the library config file
      # passed by the application.
      #
      # Functions that may return this value:
      # - #SigV4_GenerateHTTPAuthorization
      class MaxHeaderPairCountExceeded < Error; end

      # The maximum number of query parameters was exceeded while parsing
      # the query string passed to the library.
      # The maximum number of supported query parameters can be configured
      # with the SIGV4_MAX_QUERY_PAIR_COUNT macro in the library config file
      # passed by the application.
      #
      # Functions that may return this value:
      # - #SigV4_GenerateHTTPAuthorization
      class MaxQueryPairCountExceeded < Error; end

      # An error occurred while performing a hash operation.
      #
      # Functions that may return this value:
      # - #SigV4_GenerateHTTPAuthorization
      class HashError < Error; end

      # HTTP headers parsed to the library are invalid.
      #
      # Functions that may return this value:
      # - #SigV4_GenerateHTTPAuthorization
      class InvalidHttpHeaders < Error; end
    end
  end
end
