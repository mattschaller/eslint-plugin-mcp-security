import { ESLintUtils, TSESTree, AST_NODE_TYPES } from '@typescript-eslint/utils';

const createRule = ESLintUtils.RuleCreator(
  (name) =>
    `https://github.com/mattschaller/eslint-plugin-mcp-security/blob/main/docs/rules/${name}.md`,
);

const HTTP_HANDLER_METHODS = new Set([
  'get',
  'post',
  'put',
  'delete',
  'patch',
  'use',
  'all',
  'options',
  'head',
  'createServer',
]);

type MessageIds = 'mcpServerInLoop' | 'connectInHandler';

export default createRule<[], MessageIds>({
  name: 'no-mcpserver-reuse',
  meta: {
    type: 'problem',
    docs: {
      description:
        'Disallow reusing a module-scope McpServer inside request handlers (CVE-2026-25536) and instantiation in loops',
    },
    messages: {
      mcpServerInLoop:
        'new McpServer() inside a loop creates a new server instance per iteration, ' +
        'risking resource exhaustion and state confusion. ' +
        'Instantiate McpServer once or use a factory function.',
      connectInHandler:
        '.connect() called on a module-scope McpServer inside a request handler. ' +
        'Reusing a single McpServer across requests causes cross-client data leaks (CVE-2026-25536). ' +
        'Create a new McpServer per request instead.',
    },
    schema: [],
  },
  defaultOptions: [],
  create(context) {
    const httpHandlerNodes = new Set<TSESTree.Node>();
    let insideHttpHandler = 0;
    let insideLoop = 0;
    // Module-scope McpServer variable names (e.g., `const server = new McpServer(...)`)
    const moduleScopeMcpServers = new Set<string>();
    // Stack of sets: McpServer variable names created in each handler scope
    const handlerLocalMcpServers: Set<string>[] = [];

    function getLastFunctionArg(
      node: TSESTree.CallExpression,
    ): TSESTree.ArrowFunctionExpression | TSESTree.FunctionExpression | null {
      const lastArg = node.arguments[node.arguments.length - 1];
      if (!lastArg) return null;

      if (
        lastArg.type === AST_NODE_TYPES.ArrowFunctionExpression ||
        lastArg.type === AST_NODE_TYPES.FunctionExpression
      ) {
        return lastArg;
      }
      return null;
    }

    function isHttpHandlerRegistration(
      node: TSESTree.CallExpression,
    ): boolean {
      if (node.callee.type !== AST_NODE_TYPES.MemberExpression) return false;
      if (node.callee.property.type !== AST_NODE_TYPES.Identifier) return false;

      const method = node.callee.property.name;

      // Express-style: app.get(), router.post(), http.createServer()
      if (HTTP_HANDLER_METHODS.has(method)) return true;

      // Event-style: server.on('request', handler)
      if (method === 'on' && node.arguments.length >= 2) {
        const firstArg = node.arguments[0];
        if (
          firstArg.type === AST_NODE_TYPES.Literal &&
          (firstArg.value === 'request' || firstArg.value === 'connection')
        ) {
          return true;
        }
      }

      return false;
    }

    function isConnectCall(node: TSESTree.CallExpression): boolean {
      return (
        node.callee.type === AST_NODE_TYPES.MemberExpression &&
        node.callee.property.type === AST_NODE_TYPES.Identifier &&
        node.callee.property.name === 'connect'
      );
    }

    function getConnectObjectName(node: TSESTree.CallExpression): string | null {
      if (
        node.callee.type === AST_NODE_TYPES.MemberExpression &&
        node.callee.object.type === AST_NODE_TYPES.Identifier
      ) {
        return node.callee.object.name;
      }
      return null;
    }

    function isLocalMcpServer(name: string): boolean {
      for (let i = handlerLocalMcpServers.length - 1; i >= 0; i--) {
        if (handlerLocalMcpServers[i].has(name)) return true;
      }
      return false;
    }

    function trackMcpServerAssignment(node: TSESTree.NewExpression): void {
      if (handlerLocalMcpServers.length === 0) return;

      const parent = node.parent;
      if (!parent) return;

      // const server = new McpServer(...)
      if (
        parent.type === AST_NODE_TYPES.VariableDeclarator &&
        parent.id.type === AST_NODE_TYPES.Identifier
      ) {
        handlerLocalMcpServers[handlerLocalMcpServers.length - 1].add(parent.id.name);
      }
    }

    const enterFn = (node: TSESTree.Node): void => {
      if (httpHandlerNodes.has(node)) {
        insideHttpHandler++;
        handlerLocalMcpServers.push(new Set());
      }
    };

    const exitFn = (node: TSESTree.Node): void => {
      if (httpHandlerNodes.has(node)) {
        insideHttpHandler--;
        httpHandlerNodes.delete(node);
        handlerLocalMcpServers.pop();
      }
    };

    return {
      CallExpression(node) {
        if (isHttpHandlerRegistration(node)) {
          const handler = getLastFunctionArg(node);
          if (handler) {
            httpHandlerNodes.add(handler);
          }
        }

        // Flag .connect() on module-scope McpServer inside HTTP handlers
        if (insideHttpHandler > 0 && isConnectCall(node)) {
          const objectName = getConnectObjectName(node);
          // Only flag when the object is a known module-scope McpServer
          // and NOT locally created in this handler
          if (
            objectName &&
            moduleScopeMcpServers.has(objectName) &&
            !isLocalMcpServer(objectName)
          ) {
            context.report({ node, messageId: 'connectInHandler' });
          }
        }
      },
      NewExpression(node) {
        if (node.callee.type !== AST_NODE_TYPES.Identifier) return;
        if (node.callee.name !== 'McpServer') return;

        if (insideLoop > 0) {
          context.report({ node, messageId: 'mcpServerInLoop' });
        } else if (insideHttpHandler > 0) {
          // Per-request McpServer is the correct pattern — track it, don't flag it
          trackMcpServerAssignment(node);
        } else {
          // Module-scope McpServer — track the variable name for .connect() checks
          const parent = node.parent;
          if (
            parent &&
            parent.type === AST_NODE_TYPES.VariableDeclarator &&
            parent.id.type === AST_NODE_TYPES.Identifier
          ) {
            moduleScopeMcpServers.add(parent.id.name);
          }
        }
      },
      ArrowFunctionExpression: enterFn,
      'ArrowFunctionExpression:exit': exitFn,
      FunctionExpression: enterFn,
      'FunctionExpression:exit': exitFn,
      ForStatement() {
        insideLoop++;
      },
      'ForStatement:exit'() {
        insideLoop--;
      },
      WhileStatement() {
        insideLoop++;
      },
      'WhileStatement:exit'() {
        insideLoop--;
      },
      DoWhileStatement() {
        insideLoop++;
      },
      'DoWhileStatement:exit'() {
        insideLoop--;
      },
      ForInStatement() {
        insideLoop++;
      },
      'ForInStatement:exit'() {
        insideLoop--;
      },
      ForOfStatement() {
        insideLoop++;
      },
      'ForOfStatement:exit'() {
        insideLoop--;
      },
    };
  },
});
