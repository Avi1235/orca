/*
 * Copyright 2015 Netflix, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.netflix.spinnaker.orca.kato.pipeline.support

import com.netflix.spinnaker.orca.pipeline.model.Pipeline
import com.netflix.spinnaker.orca.pipeline.model.PipelineStage
import spock.lang.Specification
import spock.lang.Subject
import spock.lang.Unroll


class ResizeSupportSpec extends Specification {

  @Subject
  ResizeSupport resizeSupport

  def context
  def targetRefs

  def setup() {
    resizeSupport = new ResizeSupport(targetReferenceSupport: new TargetReferenceSupport())

    context = [
      cluster    : "testapp-asg",
      target     : "current_asg",
      regions    : ["us-west-1", "us-east-1"],
      credentials: "test"
    ]
    targetRefs = [
      new TargetReference(
        region: "us-west-1",
        asg: [
          name  : "testapp-asg-v001",
          region: "us-west-1",
          asg   : [
            minSize        : 10,
            maxSize        : 10,
            desiredCapacity: 10
          ]
        ]
      )
    ]
  }

  @Unroll
  def "should scale target capacity up or down by percentage or number"() {
    setup:
      context[method] = value
      context.action = direction
      def stage = new PipelineStage(new Pipeline(), "resizeAsg", context)

    when:
      def descriptors = resizeSupport.createResizeStageDescriptors(stage, targetRefs)

    then:
      !descriptors.empty
      descriptors[0].capacity == [min: want, max: want, desired: want] as Map

    where:
      method     | direction    | value || want
      "scalePct" | null         | 50    || 15
      "scalePct" | "scale_up"   | 50    || 15
      "scalePct" | "scale_down" | 50    || 5
      "scalePct" | "scale_down" | 100   || 0
      "scalePct" | "scale_down" | 1000  || 0
      "scaleNum" | null         | 6     || 16
      "scaleNum" | "scale_up"   | 6     || 16
      "scaleNum" | "scale_down" | 6     || 4
      "scaleNum" | "scale_down" | 100   || 0
  }

  @Unroll
  def "should derive capacity from ASG (#current) when partial values supplied in context (#specifiedCap)"() {

    setup:
      context.capacity = specifiedCap
      def stage = new PipelineStage(new Pipeline(), "resizeAsg", context)
      targetRefs[0].asg.asg = current

    when:
      def descriptors = resizeSupport.createResizeStageDescriptors(stage, targetRefs)

    then:
      !descriptors.empty
      descriptors[0].capacity == expected

    where:
      specifiedCap                       | current                                      || expected
      [min: 0]                           | [minSize: 1, maxSize: 1, desiredCapacity: 1] || [min: 0, max: 1, desired: 1]
      [max: 0]                           | [minSize: 1, maxSize: 1, desiredCapacity: 1] || [min: 0, max: 0, desired: 0]
      [max: 1]                           | [minSize: 1, maxSize: 1, desiredCapacity: 1] || [min: 1, max: 1, desired: 1]
      [min: 2]                           | [minSize: 1, maxSize: 1, desiredCapacity: 1] || [min: 2, max: 2, desired: 2]
      [min: 2]                           | [minSize: 1, maxSize: 3, desiredCapacity: 1] || [min: 2, max: 3, desired: 2]
      [min: 0, max: 2]                   | [minSize: 1, maxSize: 1, desiredCapacity: 1] || [min: 0, max: 2, desired: 1]
      [min: 0, max: 2]                   | [minSize: 1, maxSize: 3, desiredCapacity: 3] || [min: 0, max: 2, desired: 2]
      [min: "0", max: "2"]               | [minSize: 1, maxSize: 3, desiredCapacity: 3] || [min: 0, max: 2, desired: 2]
      [min: "0", max: "2", desired: "3"] | [minSize: 1, maxSize: 3, desiredCapacity: 3] || [min: 0, max: 2, desired: 3]
      [:]                                | [minSize: 1, maxSize: 3, desiredCapacity: 3] || [min: 1, max: 3, desired: 3]
  }

  def "should use GCE-specific modifications"() {
    setup:
      context.provider = "gce"
      context.scaleNum = 2
      context.action = "scale_up"
      context.target = "current_asg_dynamic"

      def stage = new PipelineStage(new Pipeline(), "resizeAsg", context)
      targetRefs[0].asg.zones = ["north-pole"]

    when:
      def descriptors = resizeSupport.createResizeStageDescriptors(stage, targetRefs)

    then:
      !descriptors.empty
      descriptors[0] == [
        action         : "scale_up",
        cluster        : "testapp-asg",
        credentials    : "test",
        numReplicas    : 12,
        provider       : "gce",
        regions        : ["us-west-1"],
        replicaPoolName: "testapp-asg-v001",
        scaleNum       : 2,
        target         : "current_asg_dynamic",
        zones          : ["north-pole"],
        asgName        : "testapp-asg-v001",
        capacity       : [min: 12, desired: 12, max: 12]
      ]
  }
}
