require 'java'

module JRuby
  StringWriter = java.io.StringWriter
  
  begin
    ClassReader = org.objectweb.asm.ClassReader
    TraceClassVisitor = org.objectweb.asm.util.TraceClassVisitor
  rescue
    ClassReader = org.jruby.org.objectweb.asm.ClassReader
    TraceClassVisitor = org.jruby.org.objectweb.asm.util.TraceClassVisitor
  end
    
  PrintWriter = java.io.PrintWriter
  Ruby = org.jruby.Ruby
  CompiledBlock = org.jruby.runtime.CompiledBlock
  ASTInspector = org.jruby.compiler.ASTInspector
  StandardASMCompiler = org.jruby.compiler.impl.StandardASMCompiler
  
  class << self
    # Get a Java integration reference to the given object
    def reference(obj); end

    # Turn a Java integration reference to a Ruby object back into a normal Ruby
    # object reference.
    def dereference(obj); end

    # Get the current JRuby runtime.
    def runtime
      # reference nil, since it is guaranteed to be a normal object
      reference0(nil).runtime
    end

    # Run the provided (required) block with the "global runtime" set to the
    # current runtime, for libraries that expect to operate against the global
    # runtime.
    def with_current_runtime_as_global
      current = runtime
      global = Ruby.global_runtime

      begin
        if current != global
          current.use_as_global_runtime
        end
        yield
      ensure
        if Ruby.global_runtime != global
          global.use_as_global_runtime
        end
      end
    end

    # Parse the given block or the provided content, returning a JRuby AST node.
    def parse(content = nil, filename = (default_filename = true; '-'), extra_position_info = false, &block)
      if block
        block_r = reference0(block)
        body = block_r.body

        if CompiledBlock === body
          raise ArgumentError, "cannot get parse tree from compiled block"
        end

        body.body_node
      else
        content = content.to_str
        filename = filename.to_str unless default_filename

        runtime.parse(reference0(content).byte_list, filename, nil, 0, extra_position_info)
      end
    end
    alias ast_for parse

    # Parse and compile the given block or provided content, returning a new
    # CompiledScript instance.
    def compile(content = nil, filename = (default_filename = true; '-'), extra_position_info = false, &block)
      node = if default_filename
        parse(content, &block)
      else
        parse(content, filename, extra_position_info, &block)
      end
      
      content = content.to_str
      filename = filename.to_str unless default_filename

      if filename == "-e"
        classname = "__dash_e__"
      else
        classname = filename.gsub(/\\/, '/')
        classname.gsub!(/\.rb/, '')
        classname.gsub!(/-/, 'dash')
      end

      inspector = ASTInspector.new
      inspector.inspect(node)

      generator = StandardASMCompiler.new(classname, filename)

      compiler = runtime.instance_config.new_compiler
      compiler.compile_root(node, generator, inspector)

      bytes = generator.class_byte_array

      script = CompiledScript.new
      script.name = filename
      script.class_name = classname
      script.original_script = content
      script.code = bytes

      script
    end
  end
  
  class CompiledScript
    attr_accessor :name, :class_name, :original_script, :code
    
    def to_s
      @original_script
    end
    
    def inspect
      "\#<JRuby::CompiledScript #{@name}>"
    end
    
    def inspect_bytecode
      writer = StringWriter.new
      reader = ClassReader.new(@code)
      tracer = TraceClassVisitor.new(PrintWriter.new(writer))
      
      reader.accept(tracer, ClassReader::SKIP_DEBUG)
      
      writer.to_s
    end
  end
end

# Load in the native bits
require 'jruby_ext'