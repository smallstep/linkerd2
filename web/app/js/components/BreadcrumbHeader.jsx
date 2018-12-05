import { friendlyTitle, isResource, singularResource } from "./util/Utils.js";

import PropTypes from "prop-types";
import React from 'react';
import ReactRouterPropTypes from 'react-router-prop-types';
import _ from 'lodash';
import { withContext } from './util/AppContext.jsx';

const routeToCrumbTitle = {
  "servicemesh": "Service Mesh",
  "overview": "Overview",
  "tap": "Tap",
  "top": "Top",
  "routes": "Top Routes"
};

class BreadcrumbHeader extends React.Component {
  static propTypes = {
    api: PropTypes.shape({
      PrefixedLink: PropTypes.func.isRequired,
    }).isRequired,
    location: ReactRouterPropTypes.location.isRequired,
    pathPrefix: PropTypes.string.isRequired
  }

  constructor(props) {
    super(props);
    this.api = this.props.api;
  }

  processResourceDetailURL(segments) {
    if (segments.length === 4) {
      let splitSegments = _.chunk(segments, 2);
      let resourceNameSegment = splitSegments[1];
      resourceNameSegment[0] = singularResource(resourceNameSegment[0]);
      return _.concat(splitSegments[0], resourceNameSegment.join('/'));
    } else {
      return segments;
    }
  }

  convertURLToBreadcrumbs(location) {
    if (location.length === 0) {
      return [];
    } else {
      let segments = location.split('/').slice(1);
      let finalSegments = this.processResourceDetailURL(segments);

      return _.map(finalSegments, segment => {
        let partialUrl = _.takeWhile(segments, s => {
          return s !== segment;
        });

        if (partialUrl.length !== segments.length) {
          partialUrl.push(segment);
        }

        return {
          link: `/${partialUrl.join("/")}`,
          segment: segment
        };
      });
    }
  }

  segmentToFriendlyTitle(segment, isResourceType) {
    if (isResourceType) {
      return routeToCrumbTitle[segment] || friendlyTitle(segment).plural;
    } else {
      return routeToCrumbTitle[segment] || segment;
    }
  }

  renderBreadcrumbSegment(segment, shouldPluralizeFirstSegment) {
    let isMeshResource = isResource(segment);

    if (isMeshResource) {
      if (!shouldPluralizeFirstSegment) {
        return friendlyTitle(segment).singular;
      }
      return this.segmentToFriendlyTitle(segment, true);
    }
    return this.segmentToFriendlyTitle(segment, false);
  }

  render() {
    let prefix = this.props.pathPrefix;
    let PrefixedLink = this.api.PrefixedLink;
    let breadcrumbs = this.convertURLToBreadcrumbs(this.props.location.pathname.replace(prefix, ""));
    let shouldPluralizeFirstSegment = breadcrumbs.length === 1;

    return _.map(breadcrumbs, (pathSegment, index) => {
      return (
        <span key={pathSegment.segment} className="breadcrumb-link">
          <PrefixedLink
            to={pathSegment.link}>
            {this.renderBreadcrumbSegment(pathSegment.segment, shouldPluralizeFirstSegment && index === 0)}
          </PrefixedLink>
          { index < _.size(breadcrumbs) - 1 ? " > " : null}
        </span>
      );
    });
  }
}

export default withContext(BreadcrumbHeader);
